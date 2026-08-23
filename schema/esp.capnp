@0xccf6bc1b3e193d3c;

enum MembershipRole {
  admin @0;
  peer @1;
}

struct Invite {
  version @0 :UInt8;
  networkId @1 :Data;
  inviteId @2 :Text;
  inviteSecret @3 :Data;
  creatorNodeId @4 :Data;
  inviterNodeId @5 :Data;
}

struct MembershipCertificate {
  version @0 :UInt8;
  networkId @1 :Data;
  subjectNodeId @2 :Data;
  subjectConnectionId @3 :Text;
  role @4 :MembershipRole;
  allowedPorts @5 :List(UInt16);
  issuerNodeId @6 :Data;
  signature @7 :Data;
}

struct NetworkPolicyCertificate {
  version @0 :UInt8;
  networkId @1 :Data;
  maxPeers @2 :UInt32;
  issuerNodeId @3 :Data;
  issuedAtUnix @4 :UInt64;
  signature @5 :Data;
}

struct RevocationCertificate {
  version @0 :UInt8;
  networkId @1 :Data;
  subjectNodeId @2 :Data;
  issuerNodeId @3 :Data;
  issuedAtUnix @4 :UInt64;
  signature @5 :Data;
}
