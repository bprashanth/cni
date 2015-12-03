// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from Kubernetes and then invokes a plugin like bridge or ipvlan
// to do the real work.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/appc/cni/pkg/ipam"
	"github.com/appc/cni/pkg/skel"
	"github.com/appc/cni/pkg/types"
	"github.com/coreos/go-iptables/iptables"
)

const (
	// directory to which we write intermediate Kubernetes netconf.
	stateDir = "/var/lib/cni/kubernetes"
)

// NetConf represents Kubernetes network configuration.
// TODO: This is currently tailored to Bridge plugins.
type NetConf struct {
	types.NetConf
	// BrName is the name of the bridge to configure, eg: cni0.
	BrName string `json:"bridge"`
	// IsGW will assign an IP to the bridge and set it up as a gateway for
	// containers under it.
	IsGW bool `json:"isGateway"`
	// IPMasq will setup iptable MASQUERADE rules in pretty much the same way
	// flannel's --ip-masq flag or the Kubernetes kubelet does.
	IPMasq bool `json:"ipMasq"`

	// Delegate is an abstract map representing the NetConf of a delegate
	// plugin. The idea is to allow a netconf to delegate to any plugin
	// such as ipvlan but currently it is tailored to just the bridge plugin.
	Delegate map[string]interface{} `json:"delegate"`
}

// Subnet is a type that understands how to stringify the PodCIDR Kubernetes
// argument.
type Subnet string

// UnmarshalText just stringifies a byte array.
func (s *Subnet) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*s = ""
		return nil
	}
	*s = Subnet(string(text))
	return nil
}

// KubernetesArgs are arguments passed via CNI_ARGS that this plugin understands.
type KubernetesArgs struct {
	// PodCIDR is the pod cidr as assigned by the node controller for a
	// particular node. The IPAM plugin must not choose from a range
	// outside this CIDR.
	PodCIDR Subnet `json:"podCIDR",omitempty`
}

func loadKubernetesNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, nil
}

// delegate the Add operation to the plugins in CNI_PATH matchin the
// type in netconf.
func delegateAdd(cid string, netconf map[string]interface{}) error {
	netconfBytes, err := json.Marshal(netconf)
	if err != nil {
		return fmt.Errorf("error serializing delegate netconf: %v", err)
	}

	// Save the rendered netconf for cmdDel.
	// TODO: can we just recompute the netconf? writing it to disk is a sure
	// shot way of matching a namespace up with the conf that created it.
	if err = saveScratchNetConf(cid, netconfBytes); err != nil {
		return err
	}
	// TODO: We can't pipe the Kubernetes specific CNI_ARGS env var through to
	// the host-local IPAM plugin, is there a better way to avoid this?
	os.Setenv("CNI_ARGS", "")
	result, err := ipam.ExecAdd(netconf["type"].(string), netconfBytes)
	if err != nil {
		return err
	}
	// print as json the IP allocated to the namespace.
	return result.Print()
}

func saveScratchNetConf(containerID string, netconf []byte) error {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, containerID)
	return ioutil.WriteFile(path, netconf, 0600)
}

func consumeScratchNetConf(containerID string) ([]byte, error) {
	path := filepath.Join(stateDir, containerID)
	defer os.Remove(path)
	return ioutil.ReadFile(path)
}

func setupNodeMasquerade() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("failed to locate iptabes: %v", err)
	}
	return ipt.AppendUnique(
		"nat", "POSTROUTING", "!", "-d", "10.0.0.0/8",
		"-m", "addrtype", "!", "--dst-type", "LOCAL",
		"-j", "MASQUERADE",
	)
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadKubernetesNetConf(args.StdinData)
	if err != nil {
		return err
	}
	kubeArgs := KubernetesArgs{}
	err = types.LoadArgs(args.Args, &kubeArgs)
	if err != nil {
		return err
	}
	if kubeArgs.PodCIDR == "" {
		return fmt.Errorf("Cannot add, require CNI_ARGS=PodCIDR..")
	}
	// TODO: unify with the flannel plugin and allow the specification
	// of a delegate plugin, only defaulting to these values.
	n.Delegate = map[string]interface{}{
		"name":      n.Name,
		"type":      "bridge",
		"bridge":    n.BrName,
		"isGateway": n.IsGW,
		"ipMasq":    n.IPMasq,
	}
	_, route, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		return err
	}
	n.Delegate["ipam"] = map[string]interface{}{
		"type":   "host-local",
		"subnet": kubeArgs.PodCIDR,
		"routes": []types.Route{
			types.Route{
				Dst: *route,
			},
		},
	}
	if n.IPMasq {
		log.Printf("Setting up node masquerade")
		if err := setupNodeMasquerade(); err != nil {
			return err
		}
	}
	return delegateAdd(args.ContainerID, n.Delegate)
}

func cmdDel(args *skel.CmdArgs) error {
	netconfBytes, err := consumeScratchNetConf(args.ContainerID)
	if err != nil {
		return err
	}

	n := &types.NetConf{}
	if err = json.Unmarshal(netconfBytes, n); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return ipam.ExecDel(n.Type, netconfBytes)
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel)
}
