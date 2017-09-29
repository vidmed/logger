package logger

import (
	"fmt"
	"github.com/Gurpartap/logrus-stack"
	"github.com/evalphobia/logrus_sentry"
	"github.com/getsentry/raven-go"
	"github.com/sirupsen/logrus"
	"github.com/stgleb/logrus-logstash-hook"
	"github.com/x-cray/logrus-prefixed-formatter"
	"net"
	"time"
)

var instance *logrus.Logger

func Set(logger *logrus.Logger) {
	instance = logger
}

func Get() *logrus.Logger {
	if instance == nil {
		return logrus.New()
	}
	return instance
}

func Init(level int) {
	instance = logrus.New()
	logLevel := logrus.AllLevels[level]
	instance.Level = logLevel

	instance.Infof("logger.Init - Logging established with level %q on stderr", logLevel)
}

func AddStackHook() {
	callerLevels := logrus.AllLevels
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}
	Get().AddHook(logrus_stack.NewHook(callerLevels, stackLevels))
}

func AddLogstashHook(host string, port int, protocol string, level int) {
	if host == "" || port == 0 {
		Get().Infof("logger.Logstash - got host (%q), port(%d). Skipping..", host, port)
		return
	}
	hostPort := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial(protocol, hostPort)

	if err != nil {
		Get().Errorf("logger.Logstash - Error dialing logstash (%s): %s", hostPort, err.Error())
	} else {
		formatter := new(prefixed.TextFormatter)
		logstashLevel := logrus.AllLevels[level]
		Get().Infof("logger.Logstash - Establish %s connection on %s", protocol, hostPort)
		hook := logrustash.New(conn, formatter)

		if err := hook.Fire(&logrus.Entry{}); err != nil {
			Get().Errorf("logger.Logstash - Error firing logstash hook: %s", err.Error())
		} else {
			Get().Infof("logger.Logstash - Add hook for logstash with level %q", logstashLevel)
			hook.SetLevel(logstashLevel)
			Get().Hooks.Add(hook)
		}
	}
}

func AddSentryHook(apiKey, secret, host, projectId, release, env string) {
	if apiKey == "" || secret == "" || host == "" || projectId == "" {
		Get().Infof("logger.Sentry - got apiKey (%q), secret (%q), host (%q), projectId (%q). Skipping..", apiKey, secret, host, projectId)
		return
	}
	dsn := fmt.Sprintf("https://%s:%s@%s/%s",
		apiKey,
		secret,
		host,
		projectId)

	Get().Infof("logger.Sentry - Adding hook to logger to url %q", dsn)

	// ---configure default client
	if err := raven.SetDSN(dsn); err != nil {
		Get().Errorf("logger.Sentry - Error setting DSN to default client %q", err.Error())
	}
	raven.SetRelease(release)
	raven.SetEnvironment(env)
	// ---

	client, err := raven.New(dsn)
	// Set basic information
	client.SetRelease(release)
	client.SetEnvironment(env)

	if err != nil {
		Get().Errorf("logger.Sentry - Error getting new Sentry client instance %q", err.Error())
	}

	hook, err := logrus_sentry.NewWithClientSentryHook(client, []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
	})

	// Add hook for collecting stack traces
	hook.StacktraceConfiguration.Enable = true
	hook.Timeout = time.Second * 5

	if err != nil {
		Get().Errorf("logger.Sentry - Error creating a hook using an initialized client %q", err.Error())
	} else {
		Get().Hooks.Add(hook)
	}
}
