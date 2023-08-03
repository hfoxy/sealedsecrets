package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var cluster string

var global = false

var namespace string

var unsealed string
var sealed string

var unseal bool
var decode bool

var reseal bool

var force bool

var help bool

func flags() {
	var unsetValue = string(0x00)

	var clusterUsage = "Kubernetes cluster name."
	var globalUsage = "Cluster-wide secret."
	var namespaceUsage = "Namespace to seal into."
	var secretUsage = "Path to secret."
	var sealedSecretUsage = "Path to sealed secret."
	var unsealUsage = "Unseal."
	var decodeUsage = "Decode to 'stringData', only works when unsealing."
	var resealUsage = "Reseal entire secret."
	var forceUsage = "Do not prompt for confirmation."
	var helpUsage = "Print this help."

	flag.StringVar(&cluster, "c", cluster, clusterUsage)
	//flag.StringVar(&cluster, "cluster", cluster, clusterUsage)
	flag.BoolVar(&global, "g", global, globalUsage)
	//flag.BoolVar(&global, "global", global, globalUsage)
	flag.StringVar(&namespace, "n", unsetValue, namespaceUsage)
	//flag.StringVar(&namespace, "namespace", unsetValue, namespaceUsage)

	flag.StringVar(&unsealed, "U", unsetValue, secretUsage)
	//flag.StringVar(&unsealed, "secret", unsetValue, secretUsage)
	flag.StringVar(&sealed, "S", unsetValue, sealedSecretUsage)
	//flag.StringVar(&sealed, "sealed", unsetValue, sealedSecretUsage)

	flag.BoolVar(&unseal, "u", false, unsealUsage)
	//flag.BoolVar(&unseal, "unseal", false, unsealUsage)
	flag.BoolVar(&decode, "D", false, decodeUsage)
	//flag.BoolVar(&decode, "decode", false, decodeUsage)

	flag.BoolVar(&reseal, "r", false, resealUsage)
	//flag.BoolVar(&reseal, "reseal", false, resealUsage)

	flag.BoolVar(&force, "F", false, forceUsage)
	//flag.BoolVar(&force, "force", false, forceUsage)

	flag.BoolVar(&help, "h", false, helpUsage)
	//flag.BoolVar(&help, "help", false, helpUsage)

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
		return
	}

	var missingRequired []string
	if cluster == unsetValue {
		missingRequired = append(missingRequired, "cluster")
	}

	if unsealed == unsetValue {
		missingRequired = append(missingRequired, "secret")
	}

	if len(missingRequired) != 0 {
		fmt.Printf("missing required args: %s\n", strings.Join(missingRequired, ", "))

		flag.Usage()
		os.Exit(0)
		return
	}
}
