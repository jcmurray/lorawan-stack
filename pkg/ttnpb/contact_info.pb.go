// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: lorawan-stack/api/contact_info.proto

package ttnpb

import (
	context "context"
	fmt "fmt"
	io "io"
	math "math"
	reflect "reflect"
	strconv "strconv"
	strings "strings"
	time "time"

	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"
	types "github.com/gogo/protobuf/types"
	golang_proto "github.com/golang/protobuf/proto"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = golang_proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type ContactType int32

const (
	CONTACT_TYPE_OTHER     ContactType = 0
	CONTACT_TYPE_ABUSE     ContactType = 1
	CONTACT_TYPE_BILLING   ContactType = 2
	CONTACT_TYPE_TECHNICAL ContactType = 3
)

var ContactType_name = map[int32]string{
	0: "CONTACT_TYPE_OTHER",
	1: "CONTACT_TYPE_ABUSE",
	2: "CONTACT_TYPE_BILLING",
	3: "CONTACT_TYPE_TECHNICAL",
}

var ContactType_value = map[string]int32{
	"CONTACT_TYPE_OTHER":     0,
	"CONTACT_TYPE_ABUSE":     1,
	"CONTACT_TYPE_BILLING":   2,
	"CONTACT_TYPE_TECHNICAL": 3,
}

func (ContactType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_3baa36b7c4d52524, []int{0}
}

type ContactMethod int32

const (
	CONTACT_METHOD_OTHER ContactMethod = 0
	CONTACT_METHOD_EMAIL ContactMethod = 1
	CONTACT_METHOD_PHONE ContactMethod = 2
)

var ContactMethod_name = map[int32]string{
	0: "CONTACT_METHOD_OTHER",
	1: "CONTACT_METHOD_EMAIL",
	2: "CONTACT_METHOD_PHONE",
}

var ContactMethod_value = map[string]int32{
	"CONTACT_METHOD_OTHER": 0,
	"CONTACT_METHOD_EMAIL": 1,
	"CONTACT_METHOD_PHONE": 2,
}

func (ContactMethod) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_3baa36b7c4d52524, []int{1}
}

type ContactInfo struct {
	ContactType          ContactType   `protobuf:"varint,1,opt,name=contact_type,json=contactType,proto3,enum=ttn.lorawan.v3.ContactType" json:"contact_type,omitempty"`
	ContactMethod        ContactMethod `protobuf:"varint,2,opt,name=contact_method,json=contactMethod,proto3,enum=ttn.lorawan.v3.ContactMethod" json:"contact_method,omitempty"`
	Value                string        `protobuf:"bytes,3,opt,name=value,proto3" json:"value,omitempty"`
	Public               bool          `protobuf:"varint,4,opt,name=public,proto3" json:"public,omitempty"`
	ValidatedAt          *time.Time    `protobuf:"bytes,5,opt,name=validated_at,json=validatedAt,proto3,stdtime" json:"validated_at,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ContactInfo) Reset()      { *m = ContactInfo{} }
func (*ContactInfo) ProtoMessage() {}
func (*ContactInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_3baa36b7c4d52524, []int{0}
}
func (m *ContactInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ContactInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ContactInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ContactInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContactInfo.Merge(m, src)
}
func (m *ContactInfo) XXX_Size() int {
	return m.Size()
}
func (m *ContactInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_ContactInfo.DiscardUnknown(m)
}

var xxx_messageInfo_ContactInfo proto.InternalMessageInfo

func (m *ContactInfo) GetContactType() ContactType {
	if m != nil {
		return m.ContactType
	}
	return CONTACT_TYPE_OTHER
}

func (m *ContactInfo) GetContactMethod() ContactMethod {
	if m != nil {
		return m.ContactMethod
	}
	return CONTACT_METHOD_OTHER
}

func (m *ContactInfo) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

func (m *ContactInfo) GetPublic() bool {
	if m != nil {
		return m.Public
	}
	return false
}

func (m *ContactInfo) GetValidatedAt() *time.Time {
	if m != nil {
		return m.ValidatedAt
	}
	return nil
}

type ContactInfoValidation struct {
	ID                   string             `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Token                string             `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	Entity               *EntityIdentifiers `protobuf:"bytes,3,opt,name=entity,proto3" json:"entity,omitempty"`
	ContactInfo          []*ContactInfo     `protobuf:"bytes,4,rep,name=contact_info,json=contactInfo,proto3" json:"contact_info,omitempty"`
	CreatedAt            *time.Time         `protobuf:"bytes,5,opt,name=created_at,json=createdAt,proto3,stdtime" json:"created_at,omitempty"`
	ExpiresAt            *time.Time         `protobuf:"bytes,6,opt,name=expires_at,json=expiresAt,proto3,stdtime" json:"expires_at,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *ContactInfoValidation) Reset()      { *m = ContactInfoValidation{} }
func (*ContactInfoValidation) ProtoMessage() {}
func (*ContactInfoValidation) Descriptor() ([]byte, []int) {
	return fileDescriptor_3baa36b7c4d52524, []int{1}
}
func (m *ContactInfoValidation) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ContactInfoValidation) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ContactInfoValidation.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ContactInfoValidation) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContactInfoValidation.Merge(m, src)
}
func (m *ContactInfoValidation) XXX_Size() int {
	return m.Size()
}
func (m *ContactInfoValidation) XXX_DiscardUnknown() {
	xxx_messageInfo_ContactInfoValidation.DiscardUnknown(m)
}

var xxx_messageInfo_ContactInfoValidation proto.InternalMessageInfo

func (m *ContactInfoValidation) GetID() string {
	if m != nil {
		return m.ID
	}
	return ""
}

func (m *ContactInfoValidation) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func (m *ContactInfoValidation) GetEntity() *EntityIdentifiers {
	if m != nil {
		return m.Entity
	}
	return nil
}

func (m *ContactInfoValidation) GetContactInfo() []*ContactInfo {
	if m != nil {
		return m.ContactInfo
	}
	return nil
}

func (m *ContactInfoValidation) GetCreatedAt() *time.Time {
	if m != nil {
		return m.CreatedAt
	}
	return nil
}

func (m *ContactInfoValidation) GetExpiresAt() *time.Time {
	if m != nil {
		return m.ExpiresAt
	}
	return nil
}

func init() {
	proto.RegisterEnum("ttn.lorawan.v3.ContactType", ContactType_name, ContactType_value)
	golang_proto.RegisterEnum("ttn.lorawan.v3.ContactType", ContactType_name, ContactType_value)
	proto.RegisterEnum("ttn.lorawan.v3.ContactMethod", ContactMethod_name, ContactMethod_value)
	golang_proto.RegisterEnum("ttn.lorawan.v3.ContactMethod", ContactMethod_name, ContactMethod_value)
	proto.RegisterType((*ContactInfo)(nil), "ttn.lorawan.v3.ContactInfo")
	golang_proto.RegisterType((*ContactInfo)(nil), "ttn.lorawan.v3.ContactInfo")
	proto.RegisterType((*ContactInfoValidation)(nil), "ttn.lorawan.v3.ContactInfoValidation")
	golang_proto.RegisterType((*ContactInfoValidation)(nil), "ttn.lorawan.v3.ContactInfoValidation")
}

func init() {
	proto.RegisterFile("lorawan-stack/api/contact_info.proto", fileDescriptor_3baa36b7c4d52524)
}
func init() {
	golang_proto.RegisterFile("lorawan-stack/api/contact_info.proto", fileDescriptor_3baa36b7c4d52524)
}

var fileDescriptor_3baa36b7c4d52524 = []byte{
	// 763 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0x3f, 0x6c, 0xfb, 0x44,
	0x14, 0xbe, 0x73, 0xf3, 0x8b, 0x7e, 0xb9, 0xb4, 0x55, 0x30, 0x25, 0xb2, 0x5c, 0xb8, 0x86, 0x00,
	0x52, 0x54, 0x51, 0x47, 0x4a, 0x27, 0x16, 0x50, 0x92, 0x5a, 0x24, 0x52, 0x9a, 0x54, 0xc6, 0x20,
	0xc1, 0x12, 0x39, 0xce, 0xc5, 0x39, 0x25, 0xf1, 0x99, 0xe4, 0x92, 0x92, 0x89, 0x0a, 0x24, 0xd4,
	0xb1, 0x12, 0x0b, 0x23, 0x82, 0xa5, 0x63, 0xc7, 0x8e, 0x15, 0x53, 0xc7, 0x4a, 0x2c, 0x9d, 0xa0,
	0xb1, 0x19, 0x3a, 0x76, 0xec, 0x88, 0xe2, 0x38, 0xff, 0x1a, 0x15, 0xfa, 0xdb, 0xfc, 0xfc, 0xbd,
	0xf7, 0xbd, 0xf7, 0x7d, 0xef, 0xe9, 0xd0, 0x87, 0x6d, 0xd6, 0x35, 0x8e, 0x0d, 0x7b, 0xaf, 0xc7,
	0x0d, 0xb3, 0x95, 0x36, 0x1c, 0x9a, 0x36, 0x99, 0xcd, 0x0d, 0x93, 0x57, 0xa9, 0xdd, 0x60, 0x8a,
	0xd3, 0x65, 0x9c, 0x89, 0x9b, 0x9c, 0xdb, 0x4a, 0x90, 0xa9, 0x0c, 0xf6, 0xe5, 0x3d, 0x8b, 0xf2,
	0x66, 0xbf, 0xa6, 0x98, 0xac, 0x93, 0xb6, 0x98, 0xc5, 0xd2, 0x7e, 0x5a, 0xad, 0xdf, 0xf0, 0x23,
	0x3f, 0xf0, 0xbf, 0x26, 0xe5, 0xf2, 0xbb, 0x16, 0x63, 0x56, 0x9b, 0xf8, 0xec, 0x86, 0x6d, 0x33,
	0x6e, 0x70, 0xca, 0xec, 0x5e, 0x80, 0x6e, 0x07, 0xe8, 0x8c, 0x83, 0x74, 0x1c, 0x3e, 0x0c, 0xc0,
	0x9d, 0xa7, 0x20, 0xa7, 0x1d, 0xd2, 0xe3, 0x46, 0xc7, 0x09, 0x12, 0x3e, 0x58, 0x15, 0x40, 0xeb,
	0xc4, 0xe6, 0xb4, 0x41, 0x49, 0x37, 0x68, 0x91, 0xfc, 0x49, 0x40, 0xd1, 0xfc, 0x44, 0x56, 0xd1,
	0x6e, 0x30, 0xf1, 0x53, 0xb4, 0x3e, 0x55, 0xc9, 0x87, 0x0e, 0x91, 0x60, 0x02, 0xa6, 0x36, 0x33,
	0xdb, 0xca, 0xb2, 0x4c, 0x25, 0x28, 0xd1, 0x87, 0x0e, 0xd1, 0xa2, 0xe6, 0x3c, 0x10, 0x0f, 0xd0,
	0xe6, 0xb4, 0xbe, 0x43, 0x78, 0x93, 0xd5, 0x25, 0xc1, 0x67, 0x78, 0xef, 0x19, 0x86, 0x43, 0x3f,
	0x49, 0xdb, 0x30, 0x17, 0x43, 0x71, 0x0b, 0xbd, 0x1a, 0x18, 0xed, 0x3e, 0x91, 0xd6, 0x12, 0x30,
	0x15, 0xd1, 0x26, 0x81, 0x18, 0x47, 0x61, 0xa7, 0x5f, 0x6b, 0x53, 0x53, 0x0a, 0x25, 0x60, 0xea,
	0xb5, 0x16, 0x44, 0x62, 0x1e, 0xad, 0x0f, 0x8c, 0x36, 0xad, 0x1b, 0x9c, 0xd4, 0xab, 0x06, 0x97,
	0x5e, 0x25, 0x60, 0x2a, 0x9a, 0x91, 0x95, 0x89, 0x41, 0xca, 0xd4, 0x20, 0x45, 0x9f, 0x1a, 0x94,
	0x0b, 0x9d, 0xfd, 0xbd, 0x03, 0xb5, 0xe8, 0xac, 0x2a, 0xcb, 0x93, 0x7f, 0x08, 0xe8, 0x9d, 0x05,
	0x23, 0xbe, 0x9a, 0x40, 0x94, 0xd9, 0x62, 0x1c, 0x09, 0xb4, 0xee, 0x1b, 0x11, 0xc9, 0x85, 0xdd,
	0xbf, 0x76, 0x84, 0xe2, 0x81, 0x26, 0x50, 0x7f, 0x48, 0xce, 0x5a, 0xc4, 0xf6, 0x15, 0x46, 0xb4,
	0x49, 0x20, 0x7e, 0x82, 0xc2, 0x63, 0x8f, 0xf9, 0xd0, 0x9f, 0x3d, 0x9a, 0x79, 0xff, 0xa9, 0x70,
	0xd5, 0x47, 0x8b, 0xf3, 0x4d, 0x68, 0x41, 0xc1, 0xa2, 0xf7, 0xe3, 0x0b, 0x93, 0x42, 0x89, 0xb5,
	0x54, 0xf4, 0x59, 0xef, 0xc7, 0x53, 0xce, 0xbc, 0xf7, 0x77, 0xf7, 0x19, 0x42, 0x66, 0x97, 0xbc,
	0xa9, 0x0b, 0x91, 0xa0, 0x26, 0xcb, 0xc7, 0x04, 0xe4, 0x3b, 0x87, 0x76, 0x49, 0x6f, 0x4c, 0x10,
	0x7e, 0x29, 0x41, 0x50, 0x93, 0xe5, 0xbb, 0xc3, 0xd9, 0x31, 0xf9, 0xc7, 0x10, 0x47, 0x62, 0xbe,
	0x52, 0xd6, 0xb3, 0x79, 0xbd, 0xaa, 0x7f, 0x7d, 0xa4, 0x56, 0x2b, 0x7a, 0x41, 0xd5, 0x62, 0x60,
	0xe5, 0x7f, 0x36, 0xf7, 0xe5, 0x17, 0x6a, 0x0c, 0x8a, 0x12, 0xda, 0x5a, 0xfa, 0x9f, 0x2b, 0x96,
	0x4a, 0xc5, 0xf2, 0xe7, 0x31, 0x41, 0x94, 0x51, 0x7c, 0x09, 0xd1, 0xd5, 0x7c, 0xa1, 0x5c, 0xcc,
	0x67, 0x4b, 0xb1, 0x35, 0x39, 0x74, 0xfa, 0x3b, 0x06, 0xbb, 0x26, 0xda, 0x58, 0x3a, 0xa9, 0x45,
	0xb2, 0x43, 0x55, 0x2f, 0x54, 0x0e, 0x66, 0xed, 0x57, 0x11, 0xf5, 0x30, 0x5b, 0x2c, 0x2d, 0x0f,
	0x10, 0x20, 0x47, 0x85, 0x4a, 0x59, 0x8d, 0x09, 0x93, 0x26, 0x99, 0x1f, 0x05, 0xf4, 0xf6, 0xa2,
	0xfd, 0xc4, 0xa2, 0x3d, 0xde, 0x1d, 0x8a, 0xdf, 0xa3, 0xb7, 0x34, 0xf2, 0x6d, 0x9f, 0xf4, 0xf8,
	0xc2, 0xdd, 0xfc, 0xff, 0xe6, 0xe5, 0x8f, 0xfe, 0x63, 0xb7, 0x73, 0xa6, 0x64, 0xe2, 0x87, 0x3f,
	0xff, 0xf9, 0x59, 0x90, 0x93, 0xd2, 0xd2, 0x0b, 0x94, 0x1e, 0xcc, 0x7b, 0xb5, 0xd0, 0xeb, 0x20,
	0x9f, 0x88, 0x2f, 0x23, 0x95, 0xe3, 0x2b, 0x8b, 0x55, 0xc7, 0xaf, 0xcb, 0xb4, 0x59, 0xe6, 0xd9,
	0x66, 0xb9, 0xdf, 0xe0, 0xf5, 0x08, 0xc3, 0x9b, 0x11, 0x86, 0xb7, 0x23, 0x0c, 0xee, 0x46, 0x18,
	0xdc, 0x8f, 0x30, 0x78, 0x18, 0x61, 0xf0, 0x38, 0xc2, 0xf0, 0xc4, 0xc5, 0xf0, 0xd4, 0xc5, 0xe0,
	0xdc, 0xc5, 0xf0, 0xc2, 0xc5, 0xe0, 0xd2, 0xc5, 0xe0, 0xca, 0xc5, 0xe0, 0xda, 0xc5, 0xf0, 0xc6,
	0xc5, 0xf0, 0xd6, 0xc5, 0xe0, 0xce, 0xc5, 0xf0, 0xde, 0xc5, 0xe0, 0xc1, 0xc5, 0xf0, 0xd1, 0xc5,
	0xe0, 0xc4, 0xc3, 0xe0, 0xd4, 0xc3, 0xf0, 0xcc, 0xc3, 0xe0, 0x17, 0x0f, 0xc3, 0x5f, 0x3d, 0x0c,
	0xce, 0x3d, 0x0c, 0x2e, 0x3c, 0x0c, 0x2f, 0x3d, 0x0c, 0xaf, 0x3c, 0x0c, 0xbf, 0xf9, 0xd8, 0x62,
	0x0a, 0x6f, 0x12, 0xde, 0xa4, 0xb6, 0xd5, 0x53, 0x6c, 0xc2, 0x8f, 0x59, 0xb7, 0x95, 0x5e, 0x7e,
	0xe4, 0x9c, 0x96, 0x95, 0xe6, 0xdc, 0x76, 0x6a, 0xb5, 0xb0, 0x2f, 0x6b, 0xff, 0xdf, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x4b, 0xca, 0x97, 0xfb, 0xc7, 0x05, 0x00, 0x00,
}

func (x ContactType) String() string {
	s, ok := ContactType_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (x ContactMethod) String() string {
	s, ok := ContactMethod_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (this *ContactInfo) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ContactInfo)
	if !ok {
		that2, ok := that.(ContactInfo)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.ContactType != that1.ContactType {
		return false
	}
	if this.ContactMethod != that1.ContactMethod {
		return false
	}
	if this.Value != that1.Value {
		return false
	}
	if this.Public != that1.Public {
		return false
	}
	if that1.ValidatedAt == nil {
		if this.ValidatedAt != nil {
			return false
		}
	} else if !this.ValidatedAt.Equal(*that1.ValidatedAt) {
		return false
	}
	return true
}
func (this *ContactInfoValidation) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ContactInfoValidation)
	if !ok {
		that2, ok := that.(ContactInfoValidation)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.ID != that1.ID {
		return false
	}
	if this.Token != that1.Token {
		return false
	}
	if !this.Entity.Equal(that1.Entity) {
		return false
	}
	if len(this.ContactInfo) != len(that1.ContactInfo) {
		return false
	}
	for i := range this.ContactInfo {
		if !this.ContactInfo[i].Equal(that1.ContactInfo[i]) {
			return false
		}
	}
	if that1.CreatedAt == nil {
		if this.CreatedAt != nil {
			return false
		}
	} else if !this.CreatedAt.Equal(*that1.CreatedAt) {
		return false
	}
	if that1.ExpiresAt == nil {
		if this.ExpiresAt != nil {
			return false
		}
	} else if !this.ExpiresAt.Equal(*that1.ExpiresAt) {
		return false
	}
	return true
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// ContactInfoRegistryClient is the client API for ContactInfoRegistry service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type ContactInfoRegistryClient interface {
	// Request validation for the non-validated contact info for the given entity.
	RequestValidation(ctx context.Context, in *EntityIdentifiers, opts ...grpc.CallOption) (*ContactInfoValidation, error)
	// Validate confirms a contact info validation.
	Validate(ctx context.Context, in *ContactInfoValidation, opts ...grpc.CallOption) (*types.Empty, error)
}

type contactInfoRegistryClient struct {
	cc *grpc.ClientConn
}

func NewContactInfoRegistryClient(cc *grpc.ClientConn) ContactInfoRegistryClient {
	return &contactInfoRegistryClient{cc}
}

func (c *contactInfoRegistryClient) RequestValidation(ctx context.Context, in *EntityIdentifiers, opts ...grpc.CallOption) (*ContactInfoValidation, error) {
	out := new(ContactInfoValidation)
	err := c.cc.Invoke(ctx, "/ttn.lorawan.v3.ContactInfoRegistry/RequestValidation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *contactInfoRegistryClient) Validate(ctx context.Context, in *ContactInfoValidation, opts ...grpc.CallOption) (*types.Empty, error) {
	out := new(types.Empty)
	err := c.cc.Invoke(ctx, "/ttn.lorawan.v3.ContactInfoRegistry/Validate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ContactInfoRegistryServer is the server API for ContactInfoRegistry service.
type ContactInfoRegistryServer interface {
	// Request validation for the non-validated contact info for the given entity.
	RequestValidation(context.Context, *EntityIdentifiers) (*ContactInfoValidation, error)
	// Validate confirms a contact info validation.
	Validate(context.Context, *ContactInfoValidation) (*types.Empty, error)
}

func RegisterContactInfoRegistryServer(s *grpc.Server, srv ContactInfoRegistryServer) {
	s.RegisterService(&_ContactInfoRegistry_serviceDesc, srv)
}

func _ContactInfoRegistry_RequestValidation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EntityIdentifiers)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContactInfoRegistryServer).RequestValidation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ttn.lorawan.v3.ContactInfoRegistry/RequestValidation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContactInfoRegistryServer).RequestValidation(ctx, req.(*EntityIdentifiers))
	}
	return interceptor(ctx, in, info, handler)
}

func _ContactInfoRegistry_Validate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ContactInfoValidation)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ContactInfoRegistryServer).Validate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ttn.lorawan.v3.ContactInfoRegistry/Validate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ContactInfoRegistryServer).Validate(ctx, req.(*ContactInfoValidation))
	}
	return interceptor(ctx, in, info, handler)
}

var _ContactInfoRegistry_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ttn.lorawan.v3.ContactInfoRegistry",
	HandlerType: (*ContactInfoRegistryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RequestValidation",
			Handler:    _ContactInfoRegistry_RequestValidation_Handler,
		},
		{
			MethodName: "Validate",
			Handler:    _ContactInfoRegistry_Validate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "lorawan-stack/api/contact_info.proto",
}

func (m *ContactInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ContactInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.ContactType != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(m.ContactType))
	}
	if m.ContactMethod != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(m.ContactMethod))
	}
	if len(m.Value) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(len(m.Value)))
		i += copy(dAtA[i:], m.Value)
	}
	if m.Public {
		dAtA[i] = 0x20
		i++
		if m.Public {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	if m.ValidatedAt != nil {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdTime(*m.ValidatedAt)))
		n1, err := github_com_gogo_protobuf_types.StdTimeMarshalTo(*m.ValidatedAt, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	return i, nil
}

func (m *ContactInfoValidation) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ContactInfoValidation) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.ID) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(len(m.ID)))
		i += copy(dAtA[i:], m.ID)
	}
	if len(m.Token) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(len(m.Token)))
		i += copy(dAtA[i:], m.Token)
	}
	if m.Entity != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(m.Entity.Size()))
		n2, err := m.Entity.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if len(m.ContactInfo) > 0 {
		for _, msg := range m.ContactInfo {
			dAtA[i] = 0x22
			i++
			i = encodeVarintContactInfo(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.CreatedAt != nil {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdTime(*m.CreatedAt)))
		n3, err := github_com_gogo_protobuf_types.StdTimeMarshalTo(*m.CreatedAt, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	if m.ExpiresAt != nil {
		dAtA[i] = 0x32
		i++
		i = encodeVarintContactInfo(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdTime(*m.ExpiresAt)))
		n4, err := github_com_gogo_protobuf_types.StdTimeMarshalTo(*m.ExpiresAt, dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	return i, nil
}

func encodeVarintContactInfo(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func NewPopulatedContactInfo(r randyContactInfo, easy bool) *ContactInfo {
	this := &ContactInfo{}
	this.ContactType = ContactType([]int32{0, 1, 2, 3}[r.Intn(4)])
	this.ContactMethod = ContactMethod([]int32{0, 1, 2}[r.Intn(3)])
	this.Value = randStringContactInfo(r)
	this.Public = bool(r.Intn(2) == 0)
	if r.Intn(10) != 0 {
		this.ValidatedAt = github_com_gogo_protobuf_types.NewPopulatedStdTime(r, easy)
	}
	if !easy && r.Intn(10) != 0 {
	}
	return this
}

func NewPopulatedContactInfoValidation(r randyContactInfo, easy bool) *ContactInfoValidation {
	this := &ContactInfoValidation{}
	this.ID = randStringContactInfo(r)
	this.Token = randStringContactInfo(r)
	if r.Intn(10) != 0 {
		this.Entity = NewPopulatedEntityIdentifiers(r, easy)
	}
	if r.Intn(10) != 0 {
		v1 := r.Intn(5)
		this.ContactInfo = make([]*ContactInfo, v1)
		for i := 0; i < v1; i++ {
			this.ContactInfo[i] = NewPopulatedContactInfo(r, easy)
		}
	}
	if r.Intn(10) != 0 {
		this.CreatedAt = github_com_gogo_protobuf_types.NewPopulatedStdTime(r, easy)
	}
	if r.Intn(10) != 0 {
		this.ExpiresAt = github_com_gogo_protobuf_types.NewPopulatedStdTime(r, easy)
	}
	if !easy && r.Intn(10) != 0 {
	}
	return this
}

type randyContactInfo interface {
	Float32() float32
	Float64() float64
	Int63() int64
	Int31() int32
	Uint32() uint32
	Intn(n int) int
}

func randUTF8RuneContactInfo(r randyContactInfo) rune {
	ru := r.Intn(62)
	if ru < 10 {
		return rune(ru + 48)
	} else if ru < 36 {
		return rune(ru + 55)
	}
	return rune(ru + 61)
}
func randStringContactInfo(r randyContactInfo) string {
	v2 := r.Intn(100)
	tmps := make([]rune, v2)
	for i := 0; i < v2; i++ {
		tmps[i] = randUTF8RuneContactInfo(r)
	}
	return string(tmps)
}
func randUnrecognizedContactInfo(r randyContactInfo, maxFieldNumber int) (dAtA []byte) {
	l := r.Intn(5)
	for i := 0; i < l; i++ {
		wire := r.Intn(4)
		if wire == 3 {
			wire = 5
		}
		fieldNumber := maxFieldNumber + r.Intn(100)
		dAtA = randFieldContactInfo(dAtA, r, fieldNumber, wire)
	}
	return dAtA
}
func randFieldContactInfo(dAtA []byte, r randyContactInfo, fieldNumber int, wire int) []byte {
	key := uint32(fieldNumber)<<3 | uint32(wire)
	switch wire {
	case 0:
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(key))
		v3 := r.Int63()
		if r.Intn(2) == 0 {
			v3 *= -1
		}
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(v3))
	case 1:
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	case 2:
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(key))
		ll := r.Intn(100)
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(ll))
		for j := 0; j < ll; j++ {
			dAtA = append(dAtA, byte(r.Intn(256)))
		}
	default:
		dAtA = encodeVarintPopulateContactInfo(dAtA, uint64(key))
		dAtA = append(dAtA, byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)))
	}
	return dAtA
}
func encodeVarintPopulateContactInfo(dAtA []byte, v uint64) []byte {
	for v >= 1<<7 {
		dAtA = append(dAtA, uint8(v&0x7f|0x80))
		v >>= 7
	}
	dAtA = append(dAtA, uint8(v))
	return dAtA
}
func (m *ContactInfo) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.ContactType != 0 {
		n += 1 + sovContactInfo(uint64(m.ContactType))
	}
	if m.ContactMethod != 0 {
		n += 1 + sovContactInfo(uint64(m.ContactMethod))
	}
	l = len(m.Value)
	if l > 0 {
		n += 1 + l + sovContactInfo(uint64(l))
	}
	if m.Public {
		n += 2
	}
	if m.ValidatedAt != nil {
		l = github_com_gogo_protobuf_types.SizeOfStdTime(*m.ValidatedAt)
		n += 1 + l + sovContactInfo(uint64(l))
	}
	return n
}

func (m *ContactInfoValidation) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.ID)
	if l > 0 {
		n += 1 + l + sovContactInfo(uint64(l))
	}
	l = len(m.Token)
	if l > 0 {
		n += 1 + l + sovContactInfo(uint64(l))
	}
	if m.Entity != nil {
		l = m.Entity.Size()
		n += 1 + l + sovContactInfo(uint64(l))
	}
	if len(m.ContactInfo) > 0 {
		for _, e := range m.ContactInfo {
			l = e.Size()
			n += 1 + l + sovContactInfo(uint64(l))
		}
	}
	if m.CreatedAt != nil {
		l = github_com_gogo_protobuf_types.SizeOfStdTime(*m.CreatedAt)
		n += 1 + l + sovContactInfo(uint64(l))
	}
	if m.ExpiresAt != nil {
		l = github_com_gogo_protobuf_types.SizeOfStdTime(*m.ExpiresAt)
		n += 1 + l + sovContactInfo(uint64(l))
	}
	return n
}

func sovContactInfo(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozContactInfo(x uint64) (n int) {
	return sovContactInfo((x << 1) ^ uint64((int64(x) >> 63)))
}
func (this *ContactInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ContactInfo{`,
		`ContactType:` + fmt.Sprintf("%v", this.ContactType) + `,`,
		`ContactMethod:` + fmt.Sprintf("%v", this.ContactMethod) + `,`,
		`Value:` + fmt.Sprintf("%v", this.Value) + `,`,
		`Public:` + fmt.Sprintf("%v", this.Public) + `,`,
		`ValidatedAt:` + strings.Replace(fmt.Sprintf("%v", this.ValidatedAt), "Timestamp", "types.Timestamp", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ContactInfoValidation) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ContactInfoValidation{`,
		`ID:` + fmt.Sprintf("%v", this.ID) + `,`,
		`Token:` + fmt.Sprintf("%v", this.Token) + `,`,
		`Entity:` + strings.Replace(fmt.Sprintf("%v", this.Entity), "EntityIdentifiers", "EntityIdentifiers", 1) + `,`,
		`ContactInfo:` + strings.Replace(fmt.Sprintf("%v", this.ContactInfo), "ContactInfo", "ContactInfo", 1) + `,`,
		`CreatedAt:` + strings.Replace(fmt.Sprintf("%v", this.CreatedAt), "Timestamp", "types.Timestamp", 1) + `,`,
		`ExpiresAt:` + strings.Replace(fmt.Sprintf("%v", this.ExpiresAt), "Timestamp", "types.Timestamp", 1) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringContactInfo(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *ContactInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowContactInfo
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ContactInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ContactInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ContactType", wireType)
			}
			m.ContactType = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ContactType |= ContactType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ContactMethod", wireType)
			}
			m.ContactMethod = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ContactMethod |= ContactMethod(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Value = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Public", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Public = bool(v != 0)
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ValidatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ValidatedAt == nil {
				m.ValidatedAt = new(time.Time)
			}
			if err := github_com_gogo_protobuf_types.StdTimeUnmarshal(m.ValidatedAt, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipContactInfo(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthContactInfo
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthContactInfo
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ContactInfoValidation) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowContactInfo
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ContactInfoValidation: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ContactInfoValidation: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Token", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Token = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Entity", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Entity == nil {
				m.Entity = &EntityIdentifiers{}
			}
			if err := m.Entity.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ContactInfo", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ContactInfo = append(m.ContactInfo, &ContactInfo{})
			if err := m.ContactInfo[len(m.ContactInfo)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CreatedAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.CreatedAt == nil {
				m.CreatedAt = new(time.Time)
			}
			if err := github_com_gogo_protobuf_types.StdTimeUnmarshal(m.CreatedAt, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExpiresAt", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthContactInfo
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthContactInfo
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.ExpiresAt == nil {
				m.ExpiresAt = new(time.Time)
			}
			if err := github_com_gogo_protobuf_types.StdTimeUnmarshal(m.ExpiresAt, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipContactInfo(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthContactInfo
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthContactInfo
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipContactInfo(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowContactInfo
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowContactInfo
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthContactInfo
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthContactInfo
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowContactInfo
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipContactInfo(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthContactInfo
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthContactInfo = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowContactInfo   = fmt.Errorf("proto: integer overflow")
)