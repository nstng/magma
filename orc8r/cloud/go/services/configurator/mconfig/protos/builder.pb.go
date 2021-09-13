// Code generated by protoc-gen-go. DO NOT EDIT.
// source: orc8r/cloud/go/services/configurator/mconfig/protos/builder.proto

package protos

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	storage "magma/orc8r/cloud/go/services/configurator/storage"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type BuildRequest struct {
	// network containing the gateway
	Network *storage.Network `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	// graph of entities associated with the gateway
	Graph *storage.EntityGraph `protobuf:"bytes,2,opt,name=graph,proto3" json:"graph,omitempty"`
	// gateway_id of the gateway
	GatewayId            string   `protobuf:"bytes,3,opt,name=gateway_id,json=gatewayId,proto3" json:"gateway_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BuildRequest) Reset()         { *m = BuildRequest{} }
func (m *BuildRequest) String() string { return proto.CompactTextString(m) }
func (*BuildRequest) ProtoMessage()    {}
func (*BuildRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_626fbded133e4155, []int{0}
}

func (m *BuildRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BuildRequest.Unmarshal(m, b)
}
func (m *BuildRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BuildRequest.Marshal(b, m, deterministic)
}
func (m *BuildRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BuildRequest.Merge(m, src)
}
func (m *BuildRequest) XXX_Size() int {
	return xxx_messageInfo_BuildRequest.Size(m)
}
func (m *BuildRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_BuildRequest.DiscardUnknown(m)
}

var xxx_messageInfo_BuildRequest proto.InternalMessageInfo

func (m *BuildRequest) GetNetwork() *storage.Network {
	if m != nil {
		return m.Network
	}
	return nil
}

func (m *BuildRequest) GetGraph() *storage.EntityGraph {
	if m != nil {
		return m.Graph
	}
	return nil
}

func (m *BuildRequest) GetGatewayId() string {
	if m != nil {
		return m.GatewayId
	}
	return ""
}

type BuildResponse struct {
	// configs_by_key contains the partial mconfig from this mconfig builder
	// Each config value contains a proto which is
	//  - first serialized to an any.Any proto
	//  - then serialized to JSON
	// TODO(#2310): remove the need to serialize to JSON by sending proto descriptors
	ConfigsByKey         map[string][]byte `protobuf:"bytes,1,rep,name=configs_by_key,json=configsByKey,proto3" json:"configs_by_key,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *BuildResponse) Reset()         { *m = BuildResponse{} }
func (m *BuildResponse) String() string { return proto.CompactTextString(m) }
func (*BuildResponse) ProtoMessage()    {}
func (*BuildResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_626fbded133e4155, []int{1}
}

func (m *BuildResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BuildResponse.Unmarshal(m, b)
}
func (m *BuildResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BuildResponse.Marshal(b, m, deterministic)
}
func (m *BuildResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BuildResponse.Merge(m, src)
}
func (m *BuildResponse) XXX_Size() int {
	return xxx_messageInfo_BuildResponse.Size(m)
}
func (m *BuildResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_BuildResponse.DiscardUnknown(m)
}

var xxx_messageInfo_BuildResponse proto.InternalMessageInfo

func (m *BuildResponse) GetConfigsByKey() map[string][]byte {
	if m != nil {
		return m.ConfigsByKey
	}
	return nil
}

func init() {
	proto.RegisterType((*BuildRequest)(nil), "magma.orc8r.configurator.mconfig.BuildRequest")
	proto.RegisterType((*BuildResponse)(nil), "magma.orc8r.configurator.mconfig.BuildResponse")
	proto.RegisterMapType((map[string][]byte)(nil), "magma.orc8r.configurator.mconfig.BuildResponse.ConfigsByKeyEntry")
}

func init() {
	proto.RegisterFile("orc8r/cloud/go/services/configurator/mconfig/protos/builder.proto", fileDescriptor_626fbded133e4155)
}

var fileDescriptor_626fbded133e4155 = []byte{
	// 346 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0xcf, 0x6b, 0x22, 0x31,
	0x14, 0xc7, 0x37, 0x8a, 0xbb, 0xf8, 0x74, 0x65, 0x37, 0xf4, 0x30, 0x08, 0x85, 0xc1, 0x93, 0x3d,
	0x34, 0x01, 0x7b, 0xb1, 0xf6, 0x50, 0x1c, 0x91, 0x52, 0x4a, 0x7b, 0x98, 0x63, 0x2f, 0x12, 0x67,
	0xd2, 0x74, 0xaa, 0x4e, 0x6c, 0x92, 0x51, 0x02, 0xfd, 0xbf, 0x4a, 0xff, 0xbb, 0x32, 0x89, 0x82,
	0xa5, 0x14, 0x6d, 0x4f, 0xef, 0x07, 0xf3, 0xfd, 0xbc, 0xef, 0xbc, 0x17, 0x18, 0x4a, 0x95, 0xf4,
	0x15, 0x4d, 0xe6, 0xb2, 0x48, 0xa9, 0x90, 0x54, 0x73, 0xb5, 0xca, 0x12, 0xae, 0x69, 0x22, 0xf3,
	0x87, 0x4c, 0x14, 0x8a, 0x19, 0xa9, 0xe8, 0xc2, 0x57, 0x74, 0xa9, 0xa4, 0x91, 0x9a, 0x4e, 0x8b,
	0x6c, 0x9e, 0x72, 0x45, 0x5c, 0x89, 0xc3, 0x05, 0x13, 0x0b, 0x46, 0x1c, 0x88, 0xec, 0xca, 0xc8,
	0x46, 0xd6, 0x1e, 0x1c, 0x34, 0x44, 0x1b, 0xa9, 0x98, 0xe0, 0xdb, 0xe8, 0xe9, 0x9d, 0x57, 0x04,
	0xcd, 0xa8, 0x9c, 0x17, 0xf3, 0xe7, 0x82, 0x6b, 0x83, 0x47, 0xf0, 0x27, 0xe7, 0x66, 0x2d, 0xd5,
	0x2c, 0x40, 0x21, 0xea, 0x36, 0x7a, 0x27, 0xe4, 0x4b, 0x03, 0x5b, 0xd4, 0x9d, 0x17, 0xc4, 0x5b,
	0x25, 0x1e, 0x41, 0x4d, 0x28, 0xb6, 0x7c, 0x0c, 0x2a, 0x0e, 0x71, 0xba, 0x1f, 0x31, 0xce, 0x4d,
	0x66, 0xec, 0x55, 0x29, 0x8a, 0xbd, 0x16, 0x1f, 0x03, 0x08, 0x66, 0xf8, 0x9a, 0xd9, 0x49, 0x96,
	0x06, 0xd5, 0x10, 0x75, 0xeb, 0x71, 0x7d, 0xd3, 0xb9, 0x4e, 0x3b, 0x6f, 0x08, 0xfe, 0x6e, 0x9c,
	0xeb, 0xa5, 0xcc, 0x35, 0xc7, 0x02, 0x5a, 0x9e, 0xad, 0x27, 0x53, 0x3b, 0x99, 0x71, 0x1b, 0xa0,
	0xb0, 0xda, 0x6d, 0xf4, 0x86, 0x64, 0xdf, 0x0a, 0xc9, 0x07, 0x10, 0x19, 0x79, 0x4a, 0x64, 0x6f,
	0xb8, 0x1d, 0xe7, 0x46, 0xd9, 0xb8, 0x99, 0xec, 0xb4, 0xda, 0x97, 0xf0, 0xff, 0xd3, 0x27, 0xf8,
	0x1f, 0x54, 0xfd, 0xc8, 0xd2, 0x67, 0x99, 0xe2, 0x23, 0xa8, 0xad, 0xd8, 0xbc, 0xe0, 0x6e, 0x0b,
	0xcd, 0xd8, 0x17, 0x83, 0x4a, 0x1f, 0xf5, 0x5e, 0xa0, 0x75, 0xeb, 0x89, 0x91, 0xbf, 0x35, 0x7e,
	0x82, 0x9a, 0x4b, 0x31, 0x39, 0xd8, 0xac, 0xbb, 0x57, 0x9b, 0x7e, 0xf3, 0xe7, 0x3a, 0xbf, 0xa2,
	0x8b, 0xfb, 0x73, 0xa7, 0xa1, 0x3f, 0x78, 0x9c, 0xd3, 0xdf, 0x2e, 0x9e, 0xbd, 0x07, 0x00, 0x00,
	0xff, 0xff, 0xab, 0x66, 0xcd, 0x83, 0xda, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// MconfigBuilderClient is the client API for MconfigBuilder service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MconfigBuilderClient interface {
	// Build returns a partial mconfig containing the gateway configs for which
	// this builder is responsible.
	Build(ctx context.Context, in *BuildRequest, opts ...grpc.CallOption) (*BuildResponse, error)
}

type mconfigBuilderClient struct {
	cc grpc.ClientConnInterface
}

func NewMconfigBuilderClient(cc grpc.ClientConnInterface) MconfigBuilderClient {
	return &mconfigBuilderClient{cc}
}

func (c *mconfigBuilderClient) Build(ctx context.Context, in *BuildRequest, opts ...grpc.CallOption) (*BuildResponse, error) {
	out := new(BuildResponse)
	err := c.cc.Invoke(ctx, "/magma.orc8r.configurator.mconfig.MconfigBuilder/Build", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MconfigBuilderServer is the server API for MconfigBuilder service.
type MconfigBuilderServer interface {
	// Build returns a partial mconfig containing the gateway configs for which
	// this builder is responsible.
	Build(context.Context, *BuildRequest) (*BuildResponse, error)
}

// UnimplementedMconfigBuilderServer can be embedded to have forward compatible implementations.
type UnimplementedMconfigBuilderServer struct {
}

func (*UnimplementedMconfigBuilderServer) Build(ctx context.Context, req *BuildRequest) (*BuildResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Build not implemented")
}

func RegisterMconfigBuilderServer(s *grpc.Server, srv MconfigBuilderServer) {
	s.RegisterService(&_MconfigBuilder_serviceDesc, srv)
}

func _MconfigBuilder_Build_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BuildRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MconfigBuilderServer).Build(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/magma.orc8r.configurator.mconfig.MconfigBuilder/Build",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MconfigBuilderServer).Build(ctx, req.(*BuildRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _MconfigBuilder_serviceDesc = grpc.ServiceDesc{
	ServiceName: "magma.orc8r.configurator.mconfig.MconfigBuilder",
	HandlerType: (*MconfigBuilderServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Build",
			Handler:    _MconfigBuilder_Build_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "orc8r/cloud/go/services/configurator/mconfig/protos/builder.proto",
}