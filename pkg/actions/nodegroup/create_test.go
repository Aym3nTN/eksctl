package nodegroup_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/pkg/errors"
	"github.com/weaveworks/eksctl/pkg/actions/nodegroup"
	api "github.com/weaveworks/eksctl/pkg/apis/eksctl.io/v1alpha5"
	"github.com/weaveworks/eksctl/pkg/cfn/manager"
	utilFakes "github.com/weaveworks/eksctl/pkg/ctl/cmdutils/filter/fakes"
	"github.com/weaveworks/eksctl/pkg/eks"
	"github.com/weaveworks/eksctl/pkg/eks/fakes"
	"github.com/weaveworks/eksctl/pkg/kubernetes"
	"github.com/weaveworks/eksctl/pkg/testutils"
	"github.com/weaveworks/eksctl/pkg/testutils/mockprovider"
)

type ngEntry struct {
	version   string
	pStatus   *eks.ProviderStatus
	mockCalls func(*mockprovider.MockProvider, *fakes.FakeKubeProvider, *fakes.FakeNodeGroupInitialiser, *utilFakes.FakeNodegroupFilter)
	expErr    error
}

var _ = DescribeTable("Create", func(t ngEntry) {
	cfg := newClusterConfig()
	cfg.Metadata.Version = t.version

	k := &fakes.FakeKubeProvider{}
	init := &fakes.FakeNodeGroupInitialiser{}
	p := mockprovider.NewMockProvider()
	ctl := &eks.ClusterProvider{
		Provider:     p,
		Status:       t.pStatus,
		KubeProvider: k,
	}
	m := nodegroup.New(cfg, ctl, nil)
	m.MockNodeGroupService(init)
	ngFilter := &utilFakes.FakeNodegroupFilter{}
	if t.mockCalls != nil {
		t.mockCalls(p, k, init, ngFilter)
	}

	err := m.Create(nodegroup.CreateOpts{}, ngFilter)
	if err != nil {
		Expect(err).To(HaveOccurred())
		Expect(err).To(MatchError(ContainSubstring(t.expErr.Error())))
		return
	}

	Expect(err).NotTo(HaveOccurred())
},
	Entry("cluster version is not supported", ngEntry{
		version: "1.14",
		pStatus: &eks.ProviderStatus{},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
		},
		expErr: fmt.Errorf("invalid version, %s is no longer supported, supported values: auto, default, latest, %s\nsee also: https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html", "1.14", strings.Join(api.SupportedVersions(), ", ")),
	}),

	Entry("fails ARM support check", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(nil, fmt.Errorf("err"))
		},
		expErr: fmt.Errorf("err"),
	}),

	Entry("fails to load VPC from config", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(&manager.StackNotFoundErr{})
		},
		expErr: errors.Wrapf(errors.New("VPC configuration required for creating nodegroups on clusters not owned by eksctl: vpc.subnets, vpc.id, vpc.securityGroup"), "loading VPC spec for cluster %q", "my-cluster"),
	}),

	Entry("cluster does not support managed nodes", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(nil)
			k.SupportsManagedNodesReturns(false, errors.New("bang"))
		},
		expErr: errors.New("bang"),
	}),

	Entry("fails when NodeGroupService fails to match instances", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(nil)
			k.SupportsManagedNodesReturns(true, nil)
			init.NewAWSSelectorSessionReturns(nil)
			init.ExpandInstanceSelectorOptionsReturns(errors.New("bang"))
		},
		expErr: errors.New("bang"),
	}),

	Entry("fails when cluster is not compatible with ng config", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(nil)
			k.SupportsManagedNodesReturns(true, nil)
			init.NewAWSSelectorSessionReturns(nil)
			init.ExpandInstanceSelectorOptionsReturns(nil)
			k.ValidateClusterForCompatibilityReturns(errors.New("bang"))
		},
		expErr: errors.Wrap(errors.New("bang"), "cluster compatibility check failed"),
	}),

	Entry("err when it fails to validate legacy subnets for ng", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(nil)
			k.SupportsManagedNodesReturns(true, nil)
			init.NewAWSSelectorSessionReturns(nil)
			init.ExpandInstanceSelectorOptionsReturns(nil)
			k.ValidateClusterForCompatibilityReturns(nil)
			init.ValidateLegacySubnetsForNodeGroupsReturns(errors.New("bang"))
		},
		expErr: errors.New("bang"),
	}),

	Entry("existing local ng stacks in config file fail to be listed", ngEntry{
		version: "1.17",
		pStatus: &eks.ProviderStatus{
			ClusterInfo: &eks.ClusterInfo{
				Cluster: testutils.NewFakeCluster("my-cluster", ""),
			},
		},
		mockCalls: func(p *mockprovider.MockProvider, k *fakes.FakeKubeProvider, init *fakes.FakeNodeGroupInitialiser, f *utilFakes.FakeNodegroupFilter) {
			k.NewRawClientReturns(&kubernetes.RawClient{}, nil)
			k.ServerVersionReturns("1.17", nil)
			k.LoadClusterIntoSpecFromStackReturns(nil)
			k.SupportsManagedNodesReturns(true, nil)
			init.NewAWSSelectorSessionReturns(nil)
			init.ExpandInstanceSelectorOptionsReturns(nil)
			k.ValidateClusterForCompatibilityReturns(nil)
			f.SetOnlyLocalReturns(errors.New("bang"))
		},
		expErr: errors.New("bang"),
	}),
)

func newClusterConfig() *api.ClusterConfig {
	return &api.ClusterConfig{
		TypeMeta: api.ClusterConfigTypeMeta(),
		Metadata: &api.ClusterMeta{
			Name:    "my-cluster",
			Version: api.DefaultVersion,
		},
		Status: &api.ClusterStatus{
			Endpoint:                 "https://localhost/",
			CertificateAuthorityData: []byte("dGVzdAo="),
		},
		IAM: api.NewClusterIAM(),
		VPC: api.NewClusterVPC(),
		CloudWatch: &api.ClusterCloudWatch{
			ClusterLogging: &api.ClusterCloudWatchLogging{},
		},
		PrivateCluster: &api.PrivateCluster{},
		NodeGroups: []*api.NodeGroup{{
			NodeGroupBase: &api.NodeGroupBase{
				Name: "my-ng",
			}},
		},
	}
}
