// Code generated by protoc-gen-go.
// source: api.proto
// DO NOT EDIT!

/*
Package stakepoolrpc is a generated protocol buffer package.

It is generated from these files:
	api.proto

It has these top-level messages:
	VersionRequest
	VersionResponse
	VoteOptionsConfigRequest
	VoteOptionsConfigResponse
*/
package stakepoolrpc

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type VersionRequest struct {
}

func (m *VersionRequest) Reset()                    { *m = VersionRequest{} }
func (m *VersionRequest) String() string            { return proto.CompactTextString(m) }
func (*VersionRequest) ProtoMessage()               {}
func (*VersionRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type VersionResponse struct {
	VersionString string `protobuf:"bytes,1,opt,name=version_string,json=versionString" json:"version_string,omitempty"`
	Major         uint32 `protobuf:"varint,2,opt,name=major" json:"major,omitempty"`
	Minor         uint32 `protobuf:"varint,3,opt,name=minor" json:"minor,omitempty"`
	Patch         uint32 `protobuf:"varint,4,opt,name=patch" json:"patch,omitempty"`
	Prerelease    string `protobuf:"bytes,5,opt,name=prerelease" json:"prerelease,omitempty"`
	BuildMetadata string `protobuf:"bytes,6,opt,name=build_metadata,json=buildMetadata" json:"build_metadata,omitempty"`
}

func (m *VersionResponse) Reset()                    { *m = VersionResponse{} }
func (m *VersionResponse) String() string            { return proto.CompactTextString(m) }
func (*VersionResponse) ProtoMessage()               {}
func (*VersionResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *VersionResponse) GetVersionString() string {
	if m != nil {
		return m.VersionString
	}
	return ""
}

func (m *VersionResponse) GetMajor() uint32 {
	if m != nil {
		return m.Major
	}
	return 0
}

func (m *VersionResponse) GetMinor() uint32 {
	if m != nil {
		return m.Minor
	}
	return 0
}

func (m *VersionResponse) GetPatch() uint32 {
	if m != nil {
		return m.Patch
	}
	return 0
}

func (m *VersionResponse) GetPrerelease() string {
	if m != nil {
		return m.Prerelease
	}
	return ""
}

func (m *VersionResponse) GetBuildMetadata() string {
	if m != nil {
		return m.BuildMetadata
	}
	return ""
}

type VoteOptionsConfigRequest struct {
}

func (m *VoteOptionsConfigRequest) Reset()                    { *m = VoteOptionsConfigRequest{} }
func (m *VoteOptionsConfigRequest) String() string            { return proto.CompactTextString(m) }
func (*VoteOptionsConfigRequest) ProtoMessage()               {}
func (*VoteOptionsConfigRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

type VoteOptionsConfigResponse struct {
	VoteInfo    string `protobuf:"bytes,1,opt,name=VoteInfo" json:"VoteInfo,omitempty"`
	VoteVersion uint32 `protobuf:"varint,2,opt,name=VoteVersion" json:"VoteVersion,omitempty"`
}

func (m *VoteOptionsConfigResponse) Reset()                    { *m = VoteOptionsConfigResponse{} }
func (m *VoteOptionsConfigResponse) String() string            { return proto.CompactTextString(m) }
func (*VoteOptionsConfigResponse) ProtoMessage()               {}
func (*VoteOptionsConfigResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *VoteOptionsConfigResponse) GetVoteInfo() string {
	if m != nil {
		return m.VoteInfo
	}
	return ""
}

func (m *VoteOptionsConfigResponse) GetVoteVersion() uint32 {
	if m != nil {
		return m.VoteVersion
	}
	return 0
}

func init() {
	proto.RegisterType((*VersionRequest)(nil), "stakepoolrpc.VersionRequest")
	proto.RegisterType((*VersionResponse)(nil), "stakepoolrpc.VersionResponse")
	proto.RegisterType((*VoteOptionsConfigRequest)(nil), "stakepoolrpc.VoteOptionsConfigRequest")
	proto.RegisterType((*VoteOptionsConfigResponse)(nil), "stakepoolrpc.VoteOptionsConfigResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for VersionService service

type VersionServiceClient interface {
	Version(ctx context.Context, in *VersionRequest, opts ...grpc.CallOption) (*VersionResponse, error)
}

type versionServiceClient struct {
	cc *grpc.ClientConn
}

func NewVersionServiceClient(cc *grpc.ClientConn) VersionServiceClient {
	return &versionServiceClient{cc}
}

func (c *versionServiceClient) Version(ctx context.Context, in *VersionRequest, opts ...grpc.CallOption) (*VersionResponse, error) {
	out := new(VersionResponse)
	err := grpc.Invoke(ctx, "/stakepoolrpc.VersionService/Version", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for VersionService service

type VersionServiceServer interface {
	Version(context.Context, *VersionRequest) (*VersionResponse, error)
}

func RegisterVersionServiceServer(s *grpc.Server, srv VersionServiceServer) {
	s.RegisterService(&_VersionService_serviceDesc, srv)
}

func _VersionService_Version_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VersionServiceServer).Version(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/stakepoolrpc.VersionService/Version",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VersionServiceServer).Version(ctx, req.(*VersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _VersionService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "stakepoolrpc.VersionService",
	HandlerType: (*VersionServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Version",
			Handler:    _VersionService_Version_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

// Client API for VoteOptionsConfigService service

type VoteOptionsConfigServiceClient interface {
	VoteOptionsConfig(ctx context.Context, in *VoteOptionsConfigRequest, opts ...grpc.CallOption) (*VoteOptionsConfigResponse, error)
}

type voteOptionsConfigServiceClient struct {
	cc *grpc.ClientConn
}

func NewVoteOptionsConfigServiceClient(cc *grpc.ClientConn) VoteOptionsConfigServiceClient {
	return &voteOptionsConfigServiceClient{cc}
}

func (c *voteOptionsConfigServiceClient) VoteOptionsConfig(ctx context.Context, in *VoteOptionsConfigRequest, opts ...grpc.CallOption) (*VoteOptionsConfigResponse, error) {
	out := new(VoteOptionsConfigResponse)
	err := grpc.Invoke(ctx, "/stakepoolrpc.VoteOptionsConfigService/VoteOptionsConfig", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for VoteOptionsConfigService service

type VoteOptionsConfigServiceServer interface {
	VoteOptionsConfig(context.Context, *VoteOptionsConfigRequest) (*VoteOptionsConfigResponse, error)
}

func RegisterVoteOptionsConfigServiceServer(s *grpc.Server, srv VoteOptionsConfigServiceServer) {
	s.RegisterService(&_VoteOptionsConfigService_serviceDesc, srv)
}

func _VoteOptionsConfigService_VoteOptionsConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VoteOptionsConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VoteOptionsConfigServiceServer).VoteOptionsConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/stakepoolrpc.VoteOptionsConfigService/VoteOptionsConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VoteOptionsConfigServiceServer).VoteOptionsConfig(ctx, req.(*VoteOptionsConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _VoteOptionsConfigService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "stakepoolrpc.VoteOptionsConfigService",
	HandlerType: (*VoteOptionsConfigServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "VoteOptionsConfig",
			Handler:    _VoteOptionsConfigService_VoteOptionsConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api.proto",
}

func init() { proto.RegisterFile("api.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 302 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xc1, 0x4e, 0x32, 0x31,
	0x14, 0x85, 0x33, 0xff, 0x2f, 0x28, 0x57, 0x41, 0x6d, 0x5c, 0xd4, 0x89, 0x1a, 0x42, 0xa2, 0xb2,
	0x62, 0x81, 0x8f, 0x60, 0x62, 0xe2, 0xc2, 0x98, 0x40, 0x42, 0x74, 0x45, 0x0a, 0x73, 0xc1, 0xea,
	0xd0, 0x5b, 0xdb, 0xc2, 0xda, 0x57, 0xf3, 0xcd, 0xcc, 0xb4, 0x65, 0x32, 0x2a, 0xc4, 0xdd, 0x9c,
	0xef, 0x4c, 0xe6, 0x9e, 0x73, 0x32, 0xd0, 0x10, 0x5a, 0xf6, 0xb4, 0x21, 0x47, 0xec, 0xc0, 0x3a,
	0xf1, 0x86, 0x9a, 0x28, 0x37, 0x7a, 0xda, 0x39, 0x82, 0xd6, 0x08, 0x8d, 0x95, 0xa4, 0x06, 0xf8,
	0xbe, 0x44, 0xeb, 0x3a, 0x9f, 0x09, 0x1c, 0x96, 0xc8, 0x6a, 0x52, 0x16, 0xd9, 0x25, 0xb4, 0x56,
	0x01, 0x8d, 0xad, 0x33, 0x52, 0xcd, 0x79, 0xd2, 0x4e, 0xba, 0x8d, 0x41, 0x33, 0xd2, 0xa1, 0x87,
	0xec, 0x04, 0x6a, 0x0b, 0xf1, 0x4a, 0x86, 0xff, 0x6b, 0x27, 0xdd, 0xe6, 0x20, 0x08, 0x4f, 0xa5,
	0x22, 0xc3, 0xff, 0x47, 0x5a, 0x88, 0x82, 0x6a, 0xe1, 0xa6, 0x2f, 0x7c, 0x27, 0x50, 0x2f, 0xd8,
	0x05, 0x80, 0x36, 0x68, 0x30, 0x47, 0x61, 0x91, 0xd7, 0xfc, 0x91, 0x0a, 0x29, 0x82, 0x4c, 0x96,
	0x32, 0xcf, 0xc6, 0x0b, 0x74, 0x22, 0x13, 0x4e, 0xf0, 0x7a, 0x08, 0xe2, 0xe9, 0x43, 0x84, 0x9d,
	0x14, 0xf8, 0x88, 0x1c, 0x3e, 0x6a, 0x27, 0x49, 0xd9, 0x5b, 0x52, 0x33, 0x39, 0x5f, 0xf7, 0x7b,
	0x86, 0xd3, 0x0d, 0x5e, 0x2c, 0x9a, 0xc2, 0x5e, 0x61, 0xde, 0xab, 0x19, 0xc5, 0x8a, 0xa5, 0x66,
	0x6d, 0xd8, 0x2f, 0x9e, 0xe3, 0x36, 0xb1, 0x63, 0x15, 0xf5, 0x9f, 0xca, 0x31, 0x87, 0x68, 0x56,
	0x72, 0x8a, 0xec, 0x0e, 0x76, 0x23, 0x61, 0x67, 0xbd, 0xea, 0xf0, 0xbd, 0xef, 0xab, 0xa7, 0xe7,
	0x5b, 0xdc, 0x90, 0xab, 0xff, 0x91, 0x6c, 0x68, 0xb4, 0x3e, 0x92, 0xc1, 0xf1, 0x2f, 0x8f, 0x5d,
	0xfd, 0xf8, 0xe0, 0x96, 0x39, 0xd2, 0xeb, 0x3f, 0xdf, 0x0b, 0x11, 0x26, 0x75, 0xff, 0xfb, 0xdc,
	0x7c, 0x05, 0x00, 0x00, 0xff, 0xff, 0x9b, 0x85, 0xe8, 0xcd, 0x4b, 0x02, 0x00, 0x00,
}