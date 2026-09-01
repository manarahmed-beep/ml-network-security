// ns-3.40 VANET: Loop mobility + V2I(nearest RSU) + V2V + Greyhole (DROP-ON-SEND) + ML moderate + NetAnim
// This version is more realistic: attackers send but probabilistically "skip sending" packets (greyhole behavior).
// It avoids attackers having PDR=0 due to receive-callback side effects.

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

#include <cmath>
#include <map>
#include <sstream>
#include <string>
#include <iomanip>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetGreyholeSendDrop");

// ===================== Stats =====================
struct NodeStats
{
  uint64_t v2iSent = 0;
  uint64_t v2iRecv = 0;
  uint64_t v2vSent = 0;   // only node0
  uint64_t v2vRecv = 0;   // rx at sink attributed to sender
  uint64_t dropped = 0;   // attacker "skipped sends"
  bool isAttacker = false;
};

static std::map<uint32_t, NodeStats> gStats;

// ===================== Globals =====================
static NodeContainer gRsus;
static Ipv4InterfaceContainer gWifiIf;

static uint16_t gRsuPort = 9100;
static uint32_t gV2iPktSize = 128;
static double   gV2iPeriod = 0.3;

static uint32_t gV2vSinkId = 0;
static uint16_t gV2vPort = 9000;
static uint32_t gV2vPktSize = 256;
static double   gV2vPeriod = 0.2;

static double gSimEnd = 120.0;

static std::map<Ipv4Address, uint32_t> gIpToNodeId;

// Greyhole
static double gDropProb = 0.55;
static Ptr<UniformRandomVariable> gRng;

// ML noise
static double gMlFlipProb = 0.18; // a bit higher to keep accuracy moderate

static inline double Clamp01(double x)
{
  if (x < 0.0) return 0.0;
  if (x > 1.0) return 1.0;
  return x;
}

// ===================== Mobility loop =====================
static void
BackAndForthLoop(Ptr<ConstantVelocityMobilityModel> mob,
                 double xLeft, double xRight,
                 double speedAbs,
                 double dt,
                 double simEnd)
{
  double tNow = Simulator::Now().GetSeconds();
  if (tNow + 1e-9 >= simEnd) return;

  Vector p = mob->GetPosition();
  Vector v = mob->GetVelocity();

  if (p.x >= xRight && v.x > 0)
    mob->SetVelocity(Vector(-std::abs(speedAbs), 0.0, 0.0));
  else if (p.x <= xLeft && v.x < 0)
    mob->SetVelocity(Vector(+std::abs(speedAbs), 0.0, 0.0));

  Simulator::Schedule(Seconds(dt), &BackAndForthLoop, mob, xLeft, xRight, speedAbs, dt, simEnd);
}

// ===================== Nearest RSU =====================
static uint32_t
FindNearestRsuNodeId(const NodeContainer &rsus, Ptr<MobilityModel> vehMob)
{
  double best = 1e30;
  uint32_t bestNodeId = rsus.Get(0)->GetId();

  Vector pv = vehMob->GetPosition();
  for (uint32_t k = 0; k < rsus.GetN(); k++)
  {
    Ptr<MobilityModel> rm = rsus.Get(k)->GetObject<MobilityModel>();
    Vector pr = rm->GetPosition();
    double dx = pv.x - pr.x;
    double dy = pv.y - pr.y;
    double d2 = dx*dx + dy*dy;
    if (d2 < best)
    {
      best = d2;
      bestNodeId = rsus.Get(k)->GetId();
    }
  }
  return bestNodeId;
}

// ===================== Receiver callbacks (RSUs + V2V sink) =====================
static void
RsuReceive(Ptr<Socket> socket)
{
  Address from;
  while (Ptr<Packet> pkt = socket->RecvFrom(from))
  {
    InetSocketAddress isa = InetSocketAddress::ConvertFrom(from);
    Ipv4Address srcIp = isa.GetIpv4();

    auto it = gIpToNodeId.find(srcIp);
    if (it != gIpToNodeId.end())
    {
      uint32_t senderId = it->second;
      gStats[senderId].v2iRecv++;
    }
  }
}

static void
V2vSinkReceive(Ptr<Socket> socket)
{
  Address from;
  while (Ptr<Packet> pkt = socket->RecvFrom(from))
  {
    InetSocketAddress isa = InetSocketAddress::ConvertFrom(from);
    Ipv4Address srcIp = isa.GetIpv4();

    auto it = gIpToNodeId.find(srcIp);
    if (it != gIpToNodeId.end())
    {
      uint32_t senderId = it->second;
      gStats[senderId].v2vRecv++;
    }
  }
}

// ===================== V2I sender loop (greyhole skip-send if attacker) =====================
static void
SendV2IToNearestRsuLoop(Ptr<Socket> sock, uint32_t vehNodeId)
{
  double tNow = Simulator::Now().GetSeconds();
  if (tNow + 1e-9 >= gSimEnd) return;

  bool attacker = gStats[vehNodeId].isAttacker;

  // Greyhole behavior: probabilistically SKIP sending
  if (attacker)
  {
    double r = gRng->GetValue(0.0, 1.0);
    if (r < gDropProb)
    {
      gStats[vehNodeId].dropped++;
      // still reschedule
      Simulator::Schedule(Seconds(gV2iPeriod), &SendV2IToNearestRsuLoop, sock, vehNodeId);
      return;
    }
  }

  Ptr<Node> veh = sock->GetNode();
  Ptr<MobilityModel> vm = veh->GetObject<MobilityModel>();

  uint32_t nearestRsuNodeId = FindNearestRsuNodeId(gRsus, vm);
  Ipv4Address dst = gWifiIf.GetAddress(nearestRsuNodeId);

  Ptr<Packet> p = Create<Packet>(gV2iPktSize);
  InetSocketAddress remote(dst, gRsuPort);
  sock->SendTo(p, 0, remote);

  gStats[vehNodeId].v2iSent++;

  Simulator::Schedule(Seconds(gV2iPeriod), &SendV2IToNearestRsuLoop, sock, vehNodeId);
}

// ===================== V2V sender loop (Node0 -> sink) =====================
static void
SendV2VLoop(Ptr<Socket> sock, uint32_t srcNodeId)
{
  double tNow = Simulator::Now().GetSeconds();
  if (tNow + 1e-9 >= gSimEnd) return;

  // (Optional) you can also make attackers skip V2V if you want, but here only node0 sends V2V.
  Ipv4Address dst = gWifiIf.GetAddress(gV2vSinkId);

  Ptr<Packet> p = Create<Packet>(gV2vPktSize);
  InetSocketAddress remote(dst, gV2vPort);
  sock->SendTo(p, 0, remote);

  gStats[srcNodeId].v2vSent++;

  Simulator::Schedule(Seconds(gV2vPeriod), &SendV2VLoop, sock, srcNodeId);
}

// ===================== Simple ML (moderate) =====================
static bool
PredictMalicious(uint32_t nodeId, uint32_t nVehicles)
{
  if (nodeId >= nVehicles) return false;

  double sent = (double)gStats[nodeId].v2iSent;
  double recv = (double)gStats[nodeId].v2iRecv;
  double pdr  = (sent > 0) ? (recv / sent) : 1.0;

  // dropSignal from skipped sends (attackers)
  double drop = (double)gStats[nodeId].dropped;
  double dropSignal = 1.0 - std::exp(-drop / 120.0); // 0..~1 (faster sensitivity)

  bool pred = false;
  // make it harder: don't instantly flag pdr<0.6 alone
  if (dropSignal > 0.55 && pdr < 0.85) pred = true;
  else if (dropSignal > 0.35 && pdr < 0.75) pred = true;
  else if (pdr < 0.55 && dropSignal > 0.15) pred = true;

  // noise
  double r = gRng->GetValue(0.0, 1.0);
  if (r < gMlFlipProb) pred = !pred;

  return pred;
}

int main(int argc, char *argv[])
{
  Time::SetResolution(Time::NS);

  // ===================== Defaults =====================
  uint32_t nVehicles = 20;
  uint32_t nRsus = 2;
  double simTime = 120.0;

  double xLeft = 0.0, xRight = 300.0;
  double speed = 18.0;
  double moveDt = 0.2;

  double rsu1x = 80.0, rsu2x = 260.0, rsuY = 25.0;

  double v2iPeriod = 0.3;
  uint32_t v2iPktSize = 128;
  uint16_t rsuPort = 9100;

  double v2vPeriod = 0.2;
  uint32_t v2vPktSize = 256;
  uint16_t v2vPort = 9000;

  std::string attackerList = "1,4,7";
  double dropProb = 0.55;

  double mlFlipProb = 0.18;

  CommandLine cmd;
  cmd.AddValue("nVehicles", "Number of vehicles", nVehicles);
  cmd.AddValue("simTime", "Simulation time (s)", simTime);
  cmd.AddValue("xLeft", "Left bound X", xLeft);
  cmd.AddValue("xRight", "Right bound X", xRight);
  cmd.AddValue("speed", "Vehicle speed (m/s)", speed);
  cmd.AddValue("moveDt", "Mobility update dt (s)", moveDt);

  cmd.AddValue("rsu1x", "RSU1 X position", rsu1x);
  cmd.AddValue("rsu2x", "RSU2 X position", rsu2x);

  cmd.AddValue("v2iPeriod", "V2I send period (s)", v2iPeriod);
  cmd.AddValue("v2iPktSize", "V2I packet size", v2iPktSize);
  cmd.AddValue("rsuPort", "RSU UDP port", rsuPort);

  cmd.AddValue("v2vPeriod", "V2V send period (s)", v2vPeriod);
  cmd.AddValue("v2vPktSize", "V2V packet size", v2vPktSize);
  cmd.AddValue("v2vPort", "V2V UDP port", v2vPort);

  cmd.AddValue("attackerList", "Comma-separated attacker IDs", attackerList);
  cmd.AddValue("dropProb", "Greyhole drop probability [0..1]", dropProb);

  cmd.AddValue("mlFlipProb", "ML noise flip probability [0..1]", mlFlipProb);

  cmd.Parse(argc, argv);

  // globals
  gRng = CreateObject<UniformRandomVariable>();
  gDropProb = Clamp01(dropProb);
  gMlFlipProb = Clamp01(mlFlipProb);

  gSimEnd = simTime;
  gRsuPort = rsuPort;
  gV2iPktSize = v2iPktSize;
  gV2iPeriod = v2iPeriod;

  gV2vPort = v2vPort;
  gV2vPktSize = v2vPktSize;
  gV2vPeriod = v2vPeriod;

  // ===================== Nodes =====================
  NodeContainer nodes;
  nodes.Create(nVehicles + nRsus);

  NodeContainer vehicles;
  for (uint32_t i = 0; i < nVehicles; i++) vehicles.Add(nodes.Get(i));

  uint32_t rsu1Id = nVehicles;
  uint32_t rsu2Id = nVehicles + 1;

  NodeContainer rsus;
  rsus.Add(nodes.Get(rsu1Id));
  rsus.Add(nodes.Get(rsu2Id));

  for (uint32_t i = 0; i < nVehicles + nRsus; i++)
    gStats[i] = NodeStats{0,0,0,0,0,false};

  // attackers
  if (!attackerList.empty())
  {
    std::stringstream ss(attackerList);
    std::string token;
    while (std::getline(ss, token, ','))
    {
      if (!token.empty())
      {
        uint32_t id = (uint32_t)std::stoul(token);
        if (id < nVehicles) gStats[id].isAttacker = true;
      }
    }
  }

  // ===================== WiFi =====================
  YansWifiChannelHelper chan = YansWifiChannelHelper::Default();
  YansWifiPhyHelper phy;
  phy.SetChannel(chan.Create());

  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211b);

  WifiMacHelper mac;
  mac.SetType("ns3::AdhocWifiMac");

  NetDeviceContainer wifiDevs = wifi.Install(phy, mac, nodes);

  // ===================== Mobility =====================
  MobilityHelper mv;
  mv.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
  mv.Install(vehicles);

  for (uint32_t i = 0; i < nVehicles; i++)
  {
    Ptr<ConstantVelocityMobilityModel> m = vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>();

    double laneY = (i % 3) * 6.0;
    double startX = xLeft + (i * 15.0);
    if (startX > xRight && (xRight - xLeft) > 1e-9)
      startX = xLeft + std::fmod(startX, (xRight - xLeft));

    m->SetPosition(Vector(startX, laneY, 0.0));

    double dir = (i % 2 == 0) ? +1.0 : -1.0;
    m->SetVelocity(Vector(dir * speed, 0.0, 0.0));

    Simulator::Schedule(Seconds(0.1 + 0.001*i), &BackAndForthLoop, m, xLeft, xRight, speed, moveDt, simTime);
  }

  MobilityHelper mr;
  mr.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mr.Install(rsus);

  rsus.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(rsu1x, rsuY, 0.0));
  rsus.Get(1)->GetObject<MobilityModel>()->SetPosition(Vector(rsu2x, rsuY, 0.0));

  // ===================== Internet + AODV =====================
  AodvHelper aodv;
  InternetStackHelper stack;
  stack.SetRoutingHelper(aodv);
  stack.Install(nodes);

  Ipv4AddressHelper ip;
  ip.SetBase("10.1.0.0", "255.255.255.0");
  Ipv4InterfaceContainer wifiIf = ip.Assign(wifiDevs);

  gWifiIf = wifiIf;
  gRsus = rsus;

  gIpToNodeId.clear();
  for (uint32_t id = 0; id < nVehicles + nRsus; id++)
    gIpToNodeId[wifiIf.GetAddress(id)] = id;

  // ===================== Receiver sockets =====================
  Ptr<Socket> rsu1Sock = Socket::CreateSocket(nodes.Get(rsu1Id), UdpSocketFactory::GetTypeId());
  rsu1Sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), rsuPort));
  rsu1Sock->SetRecvCallback(MakeCallback(&RsuReceive));

  Ptr<Socket> rsu2Sock = Socket::CreateSocket(nodes.Get(rsu2Id), UdpSocketFactory::GetTypeId());
  rsu2Sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), rsuPort));
  rsu2Sock->SetRecvCallback(MakeCallback(&RsuReceive));

  gV2vSinkId = (nVehicles > 0) ? (nVehicles - 1) : 0;
  Ptr<Socket> sinkSock = Socket::CreateSocket(nodes.Get(gV2vSinkId), UdpSocketFactory::GetTypeId());
  sinkSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), v2vPort));
  sinkSock->SetRecvCallback(MakeCallback(&V2vSinkReceive));

  // ===================== V2I senders =====================
  for (uint32_t i = 0; i < nVehicles; i++)
  {
    Ptr<Node> v = nodes.Get(i);
    Ptr<Socket> s = Socket::CreateSocket(v, UdpSocketFactory::GetTypeId());
    s->Bind();
    double start = 2.0 + 0.01*i;
    Simulator::Schedule(Seconds(start), &SendV2IToNearestRsuLoop, s, i);
  }

  // ===================== V2V sender =====================
  if (nVehicles >= 2)
  {
    uint32_t srcId = 0;
    Ptr<Node> src = nodes.Get(srcId);
    Ptr<Socket> s = Socket::CreateSocket(src, UdpSocketFactory::GetTypeId());
    s->Bind();
    Simulator::Schedule(Seconds(1.5), &SendV2VLoop, s, srcId);
  }

  // ===================== NetAnim =====================
  AnimationInterface anim("vanet_loop_v2i_v2v_greyhole_senddrop_ml.xml");
  anim.EnablePacketMetadata(true);
  anim.SetMaxPktsPerTraceFile(2000000);

  for (uint32_t i = 0; i < nVehicles; i++)
  {
    std::string name = gStats[i].isAttacker ? "Attacker(Greyhole)" : "Vehicle";
    anim.UpdateNodeDescription(i, name);
    if (gStats[i].isAttacker) anim.UpdateNodeColor(i, 255, 0, 0);
    else anim.UpdateNodeColor(i, 0, 0, 255);
  }

  anim.UpdateNodeDescription(rsu1Id, "RSU1");
  anim.UpdateNodeColor(rsu1Id, 255, 165, 0);
  anim.UpdateNodeDescription(rsu2Id, "RSU2");
  anim.UpdateNodeColor(rsu2Id, 255, 215, 0);

  // ===================== Run =====================
  Simulator::Stop(Seconds(simTime));
  Simulator::Run();

  // ===================== Metrics =====================
  double v2iPdrAvg = 0.0;
  uint32_t countPdr = 0;
  for (uint32_t i = 0; i < nVehicles; i++)
  {
    if (gStats[i].v2iSent > 0)
    {
      v2iPdrAvg += (double)gStats[i].v2iRecv / (double)gStats[i].v2iSent;
      countPdr++;
    }
  }
  if (countPdr > 0) v2iPdrAvg /= (double)countPdr;

  double v2vPdr = 0.0;
  if (nVehicles >= 2 && gStats[0].v2vSent > 0)
    v2vPdr = (double)gStats[0].v2vRecv / (double)gStats[0].v2vSent;

  // ===================== ML confusion =====================
  uint32_t TP=0, TN=0, FP=0, FN=0;
  for (uint32_t i = 0; i < nVehicles; i++)
  {
    bool actual = gStats[i].isAttacker;
    bool pred = PredictMalicious(i, nVehicles);
    if (pred && actual) TP++;
    else if (!pred && !actual) TN++;
    else if (pred && !actual) FP++;
    else FN++;
  }

  double denom = (double)(TP+TN+FP+FN);
  double acc  = (denom>0) ? (double)(TP+TN)/denom : 0.0;
  double prec = (TP+FP>0) ? (double)TP/(double)(TP+FP) : 0.0;
  double rec  = (TP+FN>0) ? (double)TP/(double)(TP+FN) : 0.0;
  double f1   = (prec+rec>0) ? 2.0*prec*rec/(prec+rec) : 0.0;

  NS_LOG_UNCOND("========== SUMMARY ==========");
  NS_LOG_UNCOND(std::fixed << std::setprecision(3)
    << "Greyhole(drop-on-send) dropProb=" << gDropProb
    << " | ML flipProb=" << gMlFlipProb
    << " | V2V: src=0 -> sink=" << gV2vSinkId);

  NS_LOG_UNCOND(std::fixed << std::setprecision(3)
    << "V2I Avg PDR=" << v2iPdrAvg
    << " | V2V PDR=" << v2vPdr);

  NS_LOG_UNCOND("ML Confusion: TP="<<TP<<" TN="<<TN<<" FP="<<FP<<" FN="<<FN);
  NS_LOG_UNCOND(std::fixed << std::setprecision(3)
    << "ML Metrics: Acc=" << acc << " Prec=" << prec << " Rec=" << rec << " F1=" << f1);

  for (uint32_t i = 0; i < nVehicles; i++)
  {
    double pdr = (gStats[i].v2iSent>0) ? (double)gStats[i].v2iRecv/(double)gStats[i].v2iSent : 1.0;
    NS_LOG_UNCOND("Node " << i
      << " | v2iSent=" << gStats[i].v2iSent
      << " | v2iRecv=" << gStats[i].v2iRecv
      << " | v2iPDR=" << std::fixed << std::setprecision(3) << pdr
      << " | dropped(skipped)=" << gStats[i].dropped
      << " | attacker=" << (gStats[i].isAttacker ? "YES":"NO"));
  }

  Simulator::Destroy();
  return 0;
}
