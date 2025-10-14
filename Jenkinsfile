properties([disableConcurrentBuilds(), buildDiscarder(logRotator(artifactDaysToKeepStr: '5', artifactNumToKeepStr: '5', daysToKeepStr: '5', numToKeepStr: '5'))])

@Library('pipeline-library')
import dk.stiil.pipeline.Constants

podTemplate(yaml: '''
    apiVersion: v1
    kind: Pod
    spec:
      containers:
      - name: buildkit
        image: moby/buildkit:v0.25.1-rootless # renovate
        command:
        - /bin/sh
        tty: true
        volumeMounts:
        - name: docker-secret
          mountPath: /home/user/.docker
        - name: certs
          mountPath: /certs/client
      - name: golang
        image: golang:1.25.3-alpine # renovate
        command:
        - sleep
        args: 
        - 99d
        env:
        - name: HOST_NAME
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: spec.nodeName
        volumeMounts:
        - name: "golang-cache"
          mountPath: "/root/.cache/"
        - name: "golang-prgs"
          mountPath: "/go/pkg/"
      restartPolicy: Never
      volumes:
      - name: docker-secret
        secret:
          secretName: github-dockercred
          items:
          - key: .dockerconfigjson
            path: config.json
      - name: certs
        secret:
          secretName: buildkit-client-certs
      - name: "golang-cache"
        persistentVolumeClaim:
          claimName: "golang-cache"
      - name: "golang-prgs"
        persistentVolumeClaim:
          claimName: "golang-prgs"
''') {
  node(POD_LABEL) {
    TreeMap scmData
    String gitCommitMessage
    Map properties
    stage('checkout SCM') {  
      scmData = checkout scm
      gitCommitMessage = sh(returnStdout: true, script: "git log --format=%B -n 1 ${scmData.GIT_COMMIT}").trim()
      gitMap = scmGetOrgRepo scmData.GIT_URL
      githubWebhookManager gitMap: gitMap, webhookTokenId: 'jenkins-webhook-repo-cleanup'
      properties = readProperties file: 'package.env'
    }
    container('golang') {
      stage('Get CA Certs') {
        sh '''
          apk --update add ca-certificates 
          cp /etc/ssl/certs/ca-certificates.crt .
        '''
      }
      stage('UnitTests') {
        withEnv(['CGO_ENABLED=0']) {
          sh '''
            go test .
          '''
        }
      }
      stage('Build Application AMD64') {
        withEnv(['CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=amd64', "PACKAGE_CONTAINER_APPLICATION=${properties.PACKAGE_CONTAINER_APPLICATION}"]) {
          sh '''
            go build -ldflags="-w -s" -o $PACKAGE_CONTAINER_APPLICATION-amd64 .
          '''
        }
      }
      stage('Build Application ARM64') {
        withEnv(['CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=arm64', "PACKAGE_CONTAINER_APPLICATION=${properties.PACKAGE_CONTAINER_APPLICATION}"]) {
          sh '''
            go build -ldflags="-w -s" -o $PACKAGE_CONTAINER_APPLICATION-arm64 .
          '''
        }
      }
    }
    if ( !gitCommitMessage.startsWith("renovate/") || ! gitCommitMessage.startsWith("WIP") ) {
      container('buildkit') {
        stage('Build Docker Image') {
          withEnv(["GIT_COMMIT=${scmData.GIT_COMMIT}", "PACKAGE_NAME=${properties.PACKAGE_NAME}", "PACKAGE_CONTAINER_PLATFORMS=${properties.PACKAGE_CONTAINER_PLATFORMS}", "PACKAGE_DESTINATION=${properties.PACKAGE_DESTINATION}", "PACKAGE_CONTAINER_SOURCE=${properties.PACKAGE_CONTAINER_SOURCE}", "GIT_BRANCH=${BRANCH_NAME}"]) {
            sh '''
              buildctl --addr 'tcp://buildkitd:1234'\
              --tlscacert /certs/client/ca.crt \
              --tlscert /certs/client/tls.crt \
              --tlskey /certs/client/tls.key \
              build \
              --frontend dockerfile.v0 \
              --opt filename=Dockerfile --opt platform=$PACKAGE_CONTAINER_PLATFORMS \
              --local context=$(pwd) --local dockerfile=$(pwd) \
              --import-cache $PACKAGE_DESTINATION/$PACKAGE_NAME:buildcache \
              --export-cache $PACKAGE_DESTINATION/$PACKAGE_NAME:buildcache \
              --output=type=image,name=$PACKAGE_DESTINATION/$PACKAGE_NAME:$BRANCH_NAME,push=true,annotation.org.opencontainers.image.description="Build based on $PACKAGE_CONTAINER_SOURCE/commit/$GIT_COMMIT",annotation.org.opencontainers.image.revision=$GIT_COMMIT,annotation.org.opencontainers.image.version=$GIT_BRANCH,annotation.org.opencontainers.image.source="https://github.com/SimonStiil/cfdyndns",annotation.org.opencontainers.image.licenses=GPL-2.0-only
              '''
          }
        }
      }
    }
  }
}