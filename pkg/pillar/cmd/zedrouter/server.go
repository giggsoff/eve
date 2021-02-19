// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// A http server providing meta-data information to application instances
// at http://169.254.169.254. The source IP address is used to tell
// which app instance is sending the request

package zedrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/iptables"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Provides a json file
type networkHandler struct {
	ctx *zedrouterContext
}

// Provides a LF-terminated text
type externalIPHandler struct {
	ctx *zedrouterContext
}

// Provides a LF-terminated text
type hostnameHandler struct {
	ctx *zedrouterContext
}

// Provides a meta-data for cloud-init
type metadataHandler struct {
	ctx *zedrouterContext
}

// Provides a user-data for cloud-init
type userDataHandler struct {
	ctx *zedrouterContext
}

// Provides links for OpenStack metadata
type openstackHandler struct {
	ctx *zedrouterContext
}

// responseWriter is a minimal wrapper for http.ResponseWriter that allows the
// written HTTP status code to be captured for logging.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func wrapResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w}
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}

	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
	rw.wroteHeader = true

	return
}

// LoggingMiddleware logs the incoming HTTP request & its duration.
func LoggingMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			wrapped := wrapResponseWriter(w)
			next.ServeHTTP(wrapped, r)
			log.Errorf("ServeHTTP LOGGER %s", r.URL.Path)
		}
		return http.HandlerFunc(fn)
	}
}

func createServer4(ctx *zedrouterContext, bridgeIP string, bridgeName string) error {
	mux := http.NewServeMux()
	nh := &networkHandler{ctx: ctx}
	mux.Handle("/eve/v1/network.json", nh)
	ipHandler := &externalIPHandler{ctx: ctx}
	mux.Handle("/eve/v1/external_ipv4", ipHandler)
	hostnameHandler := &hostnameHandler{ctx: ctx}
	mux.Handle("/eve/v1/hostname", hostnameHandler)
	metadataHandler := &metadataHandler{ctx: ctx}
	mux.Handle("/latest/meta-data/", metadataHandler)
	mux.Handle("/2009-04-04/meta-data/", metadataHandler)
	openstackHandler := &openstackHandler{ctx: ctx}
	mux.Handle("/openstack", openstackHandler)
	mux.Handle("/openstack/", openstackHandler)
	userDataHandler := &userDataHandler{ctx: ctx}
	mux.Handle("/latest/user-data", userDataHandler)
	mux.Handle("/2009-04-04/user-data", userDataHandler)

	targetPort := 80
	subnetStr := "169.254.169.254/32"
	target := fmt.Sprintf("%s:%d", bridgeIP, targetPort)
	log.Noticef("add NAT to target %s", target)
	if err := iptables.IptableCmd(log, "-t", "nat", "-I", "PREROUTING",
		"-i", bridgeName, "-p", "tcp", "-d", subnetStr,
		"--dport", strconv.Itoa(targetPort),
		"-j", "DNAT", "--to-destination", target); err != nil {
		log.Errorf("failed to add DNAT: %s", err)
	}
	doneChan := make(chan struct{})
	// Need one server per local IP address
	// XXX once we have an IPv6 bridge IP address add:
	// go runServer(mux, "tcp6", "["+bridgeIP6+"%"+bridgeName+"]")
	go runServer(mux, "tcp4", bridgeIP, doneChan)
	setDoneChan(bridgeName, bridgeIP, doneChan)
	log.Noticef("started http server on %s/%s", bridgeName, bridgeIP)
	return nil
}

func deleteServer4(ctx *zedrouterContext, bridgeIP string, bridgeName string) {
	targetPort := 80
	subnetStr := "169.254.169.254/32"
	target := fmt.Sprintf("%s:%d", bridgeIP, targetPort)
	log.Noticef("add NAT to target %s", target)
	if err := iptables.IptableCmd(log, "-t", "nat", "-D", "PREROUTING",
		"-i", bridgeName, "-p", "tcp", "-d", subnetStr,
		"--dport", strconv.Itoa(targetPort),
		"-j", "DNAT", "--to-destination", target); err != nil {
		log.Errorf("failed to delete DNAT: %s", err)
	}
	doneChan, ok := getDoneChan(bridgeName, bridgeIP)
	if !ok {
		log.Errorf("no doneChan to stop server on %s/%s",
			bridgeName, bridgeIP)
	} else {
		doneChan <- struct{}{}
		// XXX should we wait for servers to exit?
	}
	log.Noticef("stopped http server on %s/%s", bridgeName, bridgeIP)
}

// map from bridgeName/bridgeIP to doneChan
type doneChanKey struct {
	bridgeName string
	bridgeIP   string
}

var mapToDoneChan = make(map[doneChanKey]chan<- struct{})

func setDoneChan(bridgeName string, bridgeIP string, doneChan chan<- struct{}) {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	if _, exists := mapToDoneChan[key]; exists {
		log.Fatalf("setDoneChan: key already exists %+v", key)
	}
	mapToDoneChan[key] = doneChan
}

func getDoneChan(bridgeName string, bridgeIP string) (chan<- struct{}, bool) {
	key := doneChanKey{bridgeName: bridgeName, bridgeIP: bridgeIP}
	doneChan, exists := mapToDoneChan[key]
	if !exists {
		log.Errorf("getDoneChan: key does not exist %+v", key)
	} else {
		delete(mapToDoneChan, key)
	}
	return doneChan, exists
}

func runServer(mux http.Handler, network string, ipaddr string,
	doneChan <-chan struct{}) {

	// XXX no to place to specify network. Might be an issue when we
	// add IPv6?
	m := LoggingMiddleware()
	srv := http.Server{
		Addr:    ipaddr + ":80",
		Handler: m(mux),
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		<-doneChan

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			log.Noticef("server on %s shutdown failed: %s", ipaddr, err)
		}
		close(idleConnsClosed)
	}()

	if err := srv.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			log.Noticef("server on %s closed", ipaddr)
		} else {
			log.Fatalf("server on %s failed: %s", ipaddr, err)
		}
	}
	<-idleConnsClosed
}

// ServeHTTP for networkHandler provides a json return
func (hdl networkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	externalIP, code := getExternalIPForApp(hdl.ctx, remoteIP)
	var ipStr string
	var hostname string
	// Avoid returning the string <nil>
	if len(externalIP) != 0 {
		ipStr = externalIP.String()
	}
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	if anStatus != nil {
		hostname = anStatus.UUIDandVersion.UUID.String()
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	resp, _ := json.Marshal(map[string]string{
		"caller-ip":     r.RemoteAddr,
		"external-ipv4": ipStr,
		"hostname":      hostname,
		// TBD: add public-ipv4 when controller tells us
	})
	w.Write(resp)
}

// ServeHTTP for externalIPHandler provides a text IP address
func (hdl externalIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	externalIP, code := getExternalIPForApp(hdl.ctx, remoteIP)
	w.WriteHeader(code)
	w.Header().Add("Content-Type", "text/plain")
	// Avoid returning the string <nil>
	if len(externalIP) != 0 {
		resp := []byte(externalIP.String() + "\n")
		w.Write(resp)
	}
}

func getExternalIPForApp(ctx *zedrouterContext, remoteIP net.IP) (net.IP, int) {
	netstatus := lookupNetworkInstanceStatusByAppIP(ctx, remoteIP)
	if netstatus == nil {
		log.Errorf("No NetworkInstanceStatus for %s",
			remoteIP.String())
		return net.IP{}, http.StatusNotFound
	}
	if netstatus.CurrentUplinkIntf == "" {
		log.Warnf("No CurrentUplinkIntf for %s",
			remoteIP.String())
		// Nothing to report */
		return net.IP{}, http.StatusNoContent
	}
	ip, err := types.GetLocalAddrAnyNoLinkLocal(*ctx.deviceNetworkStatus,
		0, netstatus.CurrentUplinkIntf)
	if err != nil {
		log.Errorf("No externalIP for %s: %s",
			remoteIP.String(), err)
		return net.IP{}, http.StatusNoContent
	}
	return ip, http.StatusOK
}

// ServeHTTP for hostnameHandler returns text
func (hdl hostnameHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	w.Header().Add("Content-Type", "text/plain")
	if anStatus == nil {
		w.WriteHeader(http.StatusNoContent)
		log.Errorf("No AppNetworkStatus for %s",
			remoteIP.String())
	} else {
		w.WriteHeader(http.StatusOK)
		resp := []byte(anStatus.UUIDandVersion.UUID.String() + "\n")
		w.Write(resp)
	}
}

// ServeHTTP for metadataHandler returns json
func (hdl metadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("ServeHTTP metadataHandler %s", r.URL.Path)
	dirname, filename := path.Split(strings.TrimSuffix(r.URL.Path, "/"))
	dirname = strings.TrimSuffix(dirname, "/")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	var hostname string
	var id string
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	if anStatus != nil {
		hostname = anStatus.DisplayName
		id = anStatus.UUIDandVersion.UUID.String()
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	switch filename {
	case "meta-data":
		fmt.Fprintln(w, "instance-id")
		fmt.Fprintln(w, "hostname")
		fmt.Fprintln(w, "public-keys/")
	case "hostname":
		fmt.Fprintln(w, hostname)
	case "public-keys":
		fmt.Fprint(w, "0=test")
	case "0":
		if _, previousFile := path.Split(dirname); previousFile == "public-keys" {
			fmt.Fprint(w, "openssh-key")
		}
	case "openssh-key":
		log.Errorf("openssh-key %s", dirname)
		if _, previousFile := path.Split(dirname); previousFile == "0" {
			_, err := fmt.Fprintln(w, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwYIGaByqVI0M3qFHMvAs4s5aGkDKV6WfEzHuwc+7LlUpXom86qhT0RFVePHqCnTgi0UA7d92wumvol334M/bDrke/KRpkvXEmmOgUblOBM5jAXCpNyi0GjjgzFCwU0y1BIGEapr1W94GgOrbQc2VohmNVmFyvb9dh1oSOw9niWcYKH48Me0zzlqpNi3hMILUOlnBPVhbNI2HNK2V8jN6Zme+B66G7MlBT+isY0X55gTNdfwX/VngUGgeYXeWQdQe2rqQHPOnr8ms8O/7HMWGtdWJo26p67SCj9YFHv9F06WEduhhOLEzatpyHPoBrZD/+SVGz5xrKHbNjw35zJ2eXd8R4oZN5IMULEmIwpj3s6jBz8ZXAlkb3acXGdcCPF0fMFtsgGjAzOOF3TH/N5l81kvnyNOwWjg1Y63wBVLsDjujVUsJYDiriUPKE6JbZdAoXYJeWRm8j2i4Qox5cdA5ZBdywg9M+oFtuRtdIsq53He4AcTZttz+arZhgoP1mYO0=")
			if err != nil {
				log.Errorf("openssh-key error %s", err)
			}
		}
	case "instance-id":
		fmt.Fprintln(w, id)
	}
	log.Errorf("ServeHTTP metadataHandler done %s", r.URL.Path)
}

// ServeHTTP for userDataHandler returns json
func (hdl userDataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("ServeHTTP userDataHandler %s", r.URL.Path)
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	if anStatus != nil {
		appConfig := lookupAppNetworkConfig(hdl.ctx, anStatus.Key())
		if appConfig != nil {
			log.Errorf("ServeHTTP ERROR: %s", appConfig.UserData)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Add("Content-Type", "text/yaml")
	resp := []byte("#cloud-config\npassword: passw0rd\nchpasswd: { expire: False }\nssh_pwauth: True\n")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

// ServeHTTP for openstackHandler
func (hdl openstackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Errorf("ServeHTTP openstackHandler %s", r.URL.Path)
	dirname, filename := path.Split(strings.TrimSuffix(r.URL.Path, "/"))
	dirname = strings.TrimSuffix(dirname, "/")
	remoteIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	anStatus := lookupAppNetworkStatusByAppIP(hdl.ctx, remoteIP)
	var hostname string
	var id string
	if anStatus != nil {
		hostname = anStatus.DisplayName
		id = anStatus.UUIDandVersion.UUID.String()
		appConfig := lookupAppNetworkConfig(hdl.ctx, anStatus.Key())
		if appConfig != nil {
			log.Errorf("ServeHTTP ERROR: %s", appConfig.UserData)
		}
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	key := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwYIGaByqVI0M3qFHMvAs4s5aGkDKV6WfEzHuwc+7LlUpXom86qhT0RFVePHqCnTgi0UA7d92wumvol334M/bDrke/KRpkvXEmmOgUblOBM5jAXCpNyi0GjjgzFCwU0y1BIGEapr1W94GgOrbQc2VohmNVmFyvb9dh1oSOw9niWcYKH48Me0zzlqpNi3hMILUOlnBPVhbNI2HNK2V8jN6Zme+B66G7MlBT+isY0X55gTNdfwX/VngUGgeYXeWQdQe2rqQHPOnr8ms8O/7HMWGtdWJo26p67SCj9YFHv9F06WEduhhOLEzatpyHPoBrZD/+SVGz5xrKHbNjw35zJ2eXd8R4oZN5IMULEmIwpj3s6jBz8ZXAlkb3acXGdcCPF0fMFtsgGjAzOOF3TH/N5l81kvnyNOwWjg1Y63wBVLsDjujVUsJYDiriUPKE6JbZdAoXYJeWRm8j2i4Qox5cdA5ZBdywg9M+oFtuRtdIsq53He4AcTZttz+arZhgoP1mYO0="
	switch filename {
	case "openstack":
		fmt.Fprintln(w, "latest")
	case "meta_data.json":
		resp, _ := json.Marshal(map[string]interface{}{
			"uuid":         id,
			"hostname":     hostname,
			"name":         hostname,
			"launch_index": 0,
			"keys": []map[string]string{
				{
					"data": fmt.Sprintf("%s\n", key),
					"type": "ssh",
					"name": "key",
				},
			},
			"public_keys": map[string]string{
				"key": fmt.Sprintf("%s\n", key),
			},
		})
		w.Write(resp)
	case "network_data.json":
		resp, _ := json.Marshal(map[string]interface{}{
			"services": []string{},
			"networks": []string{},
		})
		w.Write(resp)
	case "user-data":
		resp := []byte("#cloud-config\npassword: passw0rd\nchpasswd: { expire: False }\nssh_pwauth: True\n")
		w.Write(resp)
	case "vendor_data.json":
		w.Write([]byte("{}"))
	}
}
