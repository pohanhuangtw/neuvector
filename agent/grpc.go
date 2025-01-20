package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	MaxRetryCount = 5               // MaxRetryCount is the number of retries before giving up
	RetryInterval = 2 * time.Second // RetryInterval is the initial wait time before retrying, will increase exponentially
)

type ScanService struct {
	scanning  utils.Set
	scanMutex sync.Mutex
}

func newScanService() *ScanService {
	return &ScanService{
		scanning: utils.NewSet(),
	}
}

func (ss *ScanService) setScanStart(id string) bool {
	ss.scanMutex.Lock()
	defer ss.scanMutex.Unlock()

	// In case a scan takes a long time to finish, ctrl will retry the request
	// Avoid triggering the same scan for such case
	if ss.scanning.Contains(id) {
		return true
	}

	ss.scanning.Add(id)
	return false
}

func (ss *ScanService) setScanDone(id string) {
	ss.scanMutex.Lock()
	defer ss.scanMutex.Unlock()

	ss.scanning.Remove(id)
}

func (ss *ScanService) runTrivy(args []string) (*bytes.Buffer, error) {
	var out, stderr bytes.Buffer
	var err error
	for attempt := 1; attempt <= MaxRetryCount; attempt++ {
		stderr.Reset()
		out.Reset()

		cmd := exec.Command("trivy", args...)
		cmd.Stderr = &stderr
		cmd.Stdout = &out
		err = cmd.Run()
		if err == nil {
			break
		}
		if attempt < MaxRetryCount {
			waitTime := time.Duration(attempt) * RetryInterval
			log.WithFields(log.Fields{"attempt": attempt, "err": err, "stderr": stderr.String()}).Info("XXXXX Attempts failed")
			time.Sleep(waitTime)
		}
	}

	return &out, err
}

func chroot(root string) (bool, error) {
	if err := unix.Chroot(root); err != nil {
		return false, fmt.Errorf("chrooting to directory %q: %w", root, err)
	}
	return true, nil
}

func (ss *ScanService) namespaceAwareExec(root string) (*bytes.Buffer, *bytes.Buffer, error) {
	nsPath := filepath.Join(filepath.Dir(root), "ns")
	trivyPath := "/usr/local/bin/trivy"
	namespaceExec := "/usr/local/bin/namespace_exec"

	args := []string{
		"-p", nsPath,
		"-b", trivyPath,
		"-n", "mnt",
		"--",
		"fs", ".", "--format", "cyclonedx",
	}

	cmd := exec.Command(namespaceExec, args...)
	cmd.Env = append(os.Environ(), "TMPDIR=.")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.WithFields(log.Fields{"err": err, "stderr": stderr.String(), "stdout": stdout.String()}).Info("OOOOO err in scanRunningTrivy")
		return &stdout, &stderr, err
	}

	log.WithFields(log.Fields{"stdout": stdout.String()}).Info("OOOOO stdout in scanRunningTrivy")
	return &stdout, &stderr, nil
}

// TODO@@ use the SBOM to scan by trivy
func (ss *ScanService) ScanGetFiles(ctx context.Context, req *share.ScanRunningRequest) (*share.ScanData, error) {
	// Use Info log level so we by default log it's scanning
	log.WithFields(log.Fields{"id": req.ID}).Info("OOOOOOO ScanGetFiles ID")

	if ss.setScanStart(req.ID) {
		log.WithFields(log.Fields{"id": req.ID}).Info("scan in progress")
		return &share.ScanData{Error: share.ScanErrorCode_ScanErrInProgress}, nil
	}

	defer ss.setScanDone(req.ID)

	var pid int
	var data share.ScanData
	var pidHost bool

	gInfoRLock()
	if req.Type == share.ScanObjectType_HOST {
		pid = 1
		pidHost = true // default
		if gInfo.hostScanCache != nil {
			data.Buffer = gInfo.hostScanCache
			data.Error = share.ScanErrorCode_ScanErrNone
		}
	} else if c, ok := gInfo.activeContainers[req.ID]; ok {
		// log.WithFields(log.Fields{"c.info": c.info, "req": req, "c.pods": c.pods.String()}).Info("XXXXX scan the container")
		log.WithFields(log.Fields{"c.pid": c.pid, "req.ID": req.ID}).Info("OOOOOO scan the container")
		pid = c.pid
		pidHost = (c.info.PidMode == "host")
		if c.scanCache != nil {
			data.Buffer = c.scanCache
			data.Error = share.ScanErrorCode_ScanErrNone
		}
		data.WorkloadMeta = &share.WorkloadMetadata{
			Name:      c.name,
			Namespace: c.domain,
		}

		// out1, err := ss.runTrivy([]string{"fs", "--format", "json", c.rootFs})
		// if err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error running Trivy scan")
		// 	return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, nil
		// }
		// log.WithFields(log.Fields{"rootFs": data.SbomMetadata.FilePaths}).Info("XXXXX FilePaths")

		// out2, err := ss.runTrivy([]string{"fs", "--format", "json", c.upperDir})
		// if err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error running Trivy scan")
		// 	return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, nil
		// }
		// log.WithFields(log.Fields{"upperDir": out2.String()}).Info("XXXXX out2")
	}
	gInfoRUnlock()

	// Use the cached buffer if it's valid
	if data.Buffer != nil {
		log.WithFields(log.Fields{"id": req.ID}).Info("return cached data")
		return &data, nil
	}

	if pid == 0 {
		log.WithFields(log.Fields{"id": req.ID}).Info("container not running")
		return &share.ScanData{Error: share.ScanErrorCode_ScanErrContainerExit}, nil
	}

	global.SYS.ReCalculateMemoryMetrics(memStatsEnforcerResetMark)

	taskReq := workerlet.WalkGetPackageRequest{
		Pid:     pid,
		Id:      req.ID,
		Kernel:  Host.Kernel,
		ObjType: req.Type,
		PidHost: pidHost,
	}

	bytesValue, _, err := walkerTask.Run(taskReq, req.ID)
	if err == nil {
		if err = json.Unmarshal(bytesValue, &data); err != nil {
			log.WithFields(log.Fields{"id": req.ID, "error": err}).Error("XXXXX")
		}
	}

	if data.Error == share.ScanErrorCode_ScanErrNone {
		gInfoLock()
		if req.Type == share.ScanObjectType_HOST {
			gInfo.hostScanCache = data.Buffer
		} else if c, ok := gInfo.activeContainers[req.ID]; ok {
			c.scanCache = data.Buffer
		}
		gInfoUnlock()
	}

	if err := ctx.Err(); err != nil {
		log.WithFields(log.Fields{"id": req.ID, "error": err}).Error("gRPC: Failed")
	}

	log.WithFields(log.Fields{"id": req.ID}).Info("return data for scanning")

	// scan trivy in the enforcer

	if data.SbomMetadata != nil {

		var errb, outb bytes.Buffer

		sbomPath := fmt.Sprintf("/tmp/neuvector/workloads/%s", req.ID)
		if err := os.MkdirAll(sbomPath, os.ModePerm); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("XXXXX error in os.MkdirAll")
			return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, fmt.Errorf("failed: %w", err)
		}

		cmd := exec.Command("bash", "/usr/local/bin/scripts/sbom.sh", data.SbomMetadata.RootDirectory)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		err := cmd.Start()
		if err != nil {
			log.WithFields(log.Fields{"err": err, "errb": errb.String()}).Error("XXXXX error in cmd.Start")
			return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, fmt.Errorf("failed to start: %s, %w", errb.String(), err)
		}
		pgid := cmd.Process.Pid
		global.SYS.AddToolProcess(pgid, pid, "ns-sbom", req.ID)
		defer global.SYS.RemoveToolProcess(pgid, false)
		if err := cmd.Wait(); err != nil {
			log.WithFields(log.Fields{"err": err, "errb": errb.String()}).Error("XXXXX error in cmd.Wait")
			return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, fmt.Errorf("failed: %s, %w", errb.String(), err)
		}
		data.SBOMBuffer = outb.Bytes()
		log.WithFields(log.Fields{"outb": outb.String(), "errb": errb.String()}).Info("XXXXX SBOMBuffer")
		// return &share.ScanData{Error: share.ScanErrorCode_ScanErrNone}, nil

		// memfd
		// sbomBuffer, stderr, err := ss.namespaceAwareExec(data.SbomMetadata.RootDirectory)
		// if err != nil {
		// 	log.WithFields(log.Fields{"error": err, "stderr": stderr.String()}).Error("XXXXX error in namespaceAwareExec")
		// 	return &data, nil
		// }
		// data.SBOMBuffer = sbomBuffer.Bytes()
		// // chroot
		// // chrootTrivy(data.SbomMetadata.RootDirectory)
		// trivyPath := "/usr/local/bin/trivy"
		// args := []string{system.NSActRun, "-f", trivyPath,
		// 	"-m", global.SYS.GetMountNamespacePath(pid)}
		// var errb, outb bytes.Buffer

		// // log.WithFields(log.Fields{"args": args}).Info("OOOOOOO Running bench script")
		// cmd := exec.Command(system.ExecNSTool, args...)
		// cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		// cmd.Stdout = &outb
		// cmd.Stderr = &errb

		// err = cmd.Start()
		// if err != nil {
		// 	log.WithFields(log.Fields{"error": err, "msg": errb.String()}).Error("cmd Start")
		// 	return nil, err
		// }

		// commandString := fmt.Sprintf("%s: %s", cmd.Path, strings.Join(cmd.Args, " "))

		// log.WithFields(log.Fields{"commandString": commandString}).Info("JJJJJJJ running command")
		// // pgid := cmd.Process.Pid
		// err = cmd.Wait()
		// if err != nil {
		// 	log.WithFields(log.Fields{"out": outb.String(), "error": err, "err": errb.String()}).Error("HHHHHHHH cmd Wait")
		// }
		// log.WithFields(log.Fields{"out": outb.String(), "err": errb.String()}).Info("JJJJJJJ result after running trivy")

		// script := "/usr/local/bin/trivy --version"

		// log.WithFields(log.Fields{"script": script, "pid": pid}).Info("XXXXX in run script")
		// file, err := os.CreateTemp(os.TempDir(), "script")
		// if err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error in run script")
		// }
		// defer os.Remove(file.Name())
		// if _, err = file.WriteString(script); err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error in run script")
		// }
		// if err = file.Close(); err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error in run script")
		// }

		// args := []string{system.NSActRun, "-f", file.Name(),
		// 	"-m", global.SYS.GetMountNamespacePath(pid),
		// 	"-t", global.SYS.GetUtsNamespacePath(pid),
		// 	"-c", global.SYS.GetIpcNamespacePath(pid),
		// 	//"-u", global.SYS.GetUserNamespacePath(pid),
		// 	"-p", global.SYS.GetPidNamespacePath(pid),
		// 	"-n", global.SYS.GetNetNamespacePath(pid),
		// 	"-g", global.SYS.GetCgroupNamespacePath(pid),
		// }
		// var errb, outb bytes.Buffer

		// cmd := exec.Command(system.ExecNSTool, args...)
		// cmd.Stdout = &outb
		// cmd.Stderr = &errb

		// err = cmd.Start()
		// if err != nil {
		// 	log.WithFields(log.Fields{"err": err}).Error("XXXXX error in run script")
		// 	// return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, nil
		// }

		// err = cmd.Wait()
		// log.WithFields(log.Fields{"out": outb.String(), "err": errb.String()}).Info("XXXXX out after nstool")
	}

	// if data.SbomMetadata != nil {
	// 	log.WithFields(log.Fields{"sbom": data.SbomMetadata}).Info("XXXXX SbomMetadata")
	// 	// tmpDir, _ := ss.MountAndCleanFiles(data.SbomMetadata.FilePaths)
	// 	// log.WithFields(log.Fields{"tmpDir": tmpDir}).Info("XXXXX tmpDir")

	// 	mountPoint, err := ss.MountContainerFS(data.SbomMetadata.RootDirectory)
	// 	if err != nil {
	// 		log.WithFields(log.Fields{"err": err}).Error("XXXXX error mounting container fs")
	// 		return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, nil
	// 	}

	// 	out, err := ss.runTrivy([]string{"fs", "--format", "json", mountPoint})
	// 	if err != nil {
	// 		log.WithFields(log.Fields{"err": err}).Error("XXXXX error running Trivy scan")
	// 		return &share.ScanData{Error: share.ScanErrorCode_ScanErrFileSystem}, nil
	// 	} else {
	// 		log.WithFields(log.Fields{"out": out.String(), "mountPoint": mountPoint}).Info("XXXXX success running Trivy scan with mount point")
	// 	}
	// } else {
	// 	log.WithFields(log.Fields{"sbom": data.SbomMetadata}).Info("XXXXX SbomMetadata is nil")
	// }

	return &data, nil
}

type CapService struct {
}

func (s *CapService) IsGRPCCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func startGRPCServer(port uint16) (*cluster.GRPCServer, uint16) {
	var grpc *cluster.GRPCServer
	var err error

	if port == 0 {
		port = cluster.DefaultAgentGRPCPort
	}

	log.WithFields(log.Fields{"port": port}).Info("")
	for {
		grpc, err = cluster.NewGRPCServerTCP(fmt.Sprintf(":%d", port))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}

	share.RegisterEnforcerCapServiceServer(grpc.GetServer(), new(CapService))
	share.RegisterEnforcerServiceServer(grpc.GetServer(), new(RPCService))
	share.RegisterEnforcerScanServiceServer(grpc.GetServer(), newScanService())
	go grpc.Start()

	log.Info("GRPC server started")

	return grpc, port
}

func createControllerAgentServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerAgentServiceClient(conn)
}

func getControllerServiceClient() (share.ControllerAgentServiceClient, error) {
	ctrlEndpoint := getLeadGRPCEndpoint()
	log.WithFields(log.Fields{"endpoint": ctrlEndpoint}).Debug("")

	if ctrlEndpoint == "" {
		log.WithFields(log.Fields{"endpoint": ctrlEndpoint}).Error("Controller endpoint is not ready")
		return nil, fmt.Errorf("Controller endpoint is not ready")
	}
	if cluster.GetGRPCClientEndpoint(ctrlEndpoint) == "" {
		dbgError := cluster.CreateGRPCClient(ctrlEndpoint, ctrlEndpoint, true,
			createControllerAgentServiceWrapper)
		if dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	c, err := cluster.GetGRPCClient(ctrlEndpoint, cluster.IsControllerGRPCCommpressed, nil)
	if err == nil {
		return c.(share.ControllerAgentServiceClient), nil
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

func requestAdmission(req *share.CLUSAdmissionRequest, timeout time.Duration) (*share.CLUSAdmissionResponse, error) {
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return nil, fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return client.RequestAdmission(ctx, req)
}

func sendLearnedProcess(procs []*share.CLUSProcProfileReq) error {
	log.WithFields(log.Fields{"processes": len(procs)}).Debug("")

	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	procArray := &share.CLUSProcProfileArray{
		Processes: procs,
	}

	_, err = client.ReportProcProfile(ctx, procArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report process profile to controller")
		return fmt.Errorf("Fail to report process profile to controller")
	}
	return nil
}

func sendLearnedFileAccessRule(rules []*share.CLUSFileAccessRuleReq) error {
	log.WithFields(log.Fields{"rules": len(rules)}).Debug("")
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	ruleArray := &share.CLUSFileAccessRuleArray{
		Rules: rules,
	}

	_, err = client.ReportFileAccessRule(ctx, ruleArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report file rule to controller")
		return fmt.Errorf("Fail to report file rule to controller")
	}
	return nil
}

func sendConnections(conns []*share.CLUSConnection) (*share.CLUSReportResponse, error) {
	client, err := getControllerServiceClient()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to find ctrl client")
		return nil, fmt.Errorf("Fail to find controller client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	connArray := &share.CLUSConnectionArray{
		Connections: conns,
	}

	resp, err := client.ReportConnections(ctx, connArray)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Fail to report connections to controller")
		return resp, fmt.Errorf("Fail to report connections to controller")
	}
	return resp, nil
}
