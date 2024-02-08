package version

import (
	"fmt"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
)

var (
	Version        = "dev"
	CommitHash     = "n/a"
	BuildTimestamp = "n/a"
	Release        = "false"
)

var (
	Environment = "dev"
)

func init() {
	buildInfo, ok := debug.ReadBuildInfo()
	if Version == "dev" && ok {
		Version = defaultRelease()
	}

	if CommitHash == "n/a" && ok {
		CommitHash = buildInfo.Main.Sum
	}
}

func BuildVersion() string {
	return fmt.Sprintf("%s-%s (%s)", Version, CommitHash, BuildTimestamp)
}

// defaultRelease returns a release string derived from the environment. Taken from Sentry's Go SDK & modified slightly.
func defaultRelease() (release string) {
	// Return first non-empty environment variable known to hold release info, if any.
	envs := []string{
		"SENTRY_RELEASE",
		"HEROKU_SLUG_COMMIT",
		"SOURCE_VERSION",
		"CODEBUILD_RESOLVED_SOURCE_VERSION",
		"CIRCLE_SHA1",
		"GAE_DEPLOYMENT_ID",
		"GITHUB_SHA",             // GitHub Actions - https://help.github.com/en/actions
		"COMMIT_REF",             // Netlify - https://docs.netlify.com/
		"VERCEL_GIT_COMMIT_SHA",  // Vercel - https://vercel.com/
		"ZEIT_GITHUB_COMMIT_SHA", // Zeit (now known as Vercel)
		"ZEIT_GITLAB_COMMIT_SHA",
		"ZEIT_BITBUCKET_COMMIT_SHA",
	}
	for _, e := range envs {
		if release = os.Getenv(e); release != "" {
			return release
		}
	}

	buildInfo, ok := debug.ReadBuildInfo()

	// Derive a version string from Git. Example outputs:
	// 	v1.0.1-0-g9de4
	// 	v2.0-8-g77df-dirty
	// 	4f72d7
	cmd := exec.Command("git", "describe", "--long", "--always", "--dirty")
	b, err := cmd.Output()
	if err != nil {
		if ok {
			return buildInfo.Main.Version
		} else {
			return "unknown"
		}
	}

	release = strings.TrimSpace(string(b))
	return release
}
