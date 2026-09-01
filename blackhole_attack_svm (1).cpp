/* 
 * FULL MERGED VERSION
 * VANET + Blackhole + Multi-Hub IDS + SVM Classifier + Live Detection Coloring
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"

#include <fstream>
#include <set>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("VanetBlackholeSim");

static std::vector<uint64_t> txPackets;
static std::vector<uint64_t> rxPackets;
static std::vector<uint64_t> sinkDroppedPackets;

void WriteCsv(const std::string &filename, uint32_t nNodes, const std::vector<uint32_t> &isMalicious)
{
    std::ofstream out(filename.c_str());
    out << "node,isMalicious,txPackets,rxPackets,sinkDroppedPackets\n";
    for (uint32_t i = 0; i < nNodes; ++i)
    {
        out << i << "," << isMalicious[i] << "," << txPackets[i] 
            << "," << rxPackets[i] << "," << sinkDroppedPackets[i] << "\n";
    }
    out.close();
}

// -------------------------------------------------------
// Malicious Sink
// -------------------------------------------------------
class MaliciousSink : public Application
{
public:
    MaliciousSink() : m_socket(0), m_nodeId(0) {}
    virtual ~MaliciousSink() { m_socket = 0; }

    void Setup(Address address, uint32_t nodeId)
    {
        m_address = address;
        m_nodeId = nodeId;
    }

    virtual void StartApplication()
    {
        if (!m_socket)
        {
            m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
            InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 8080);
            m_socket->Bind(local);
            m_socket->SetRecvCallback(MakeCallback(&MaliciousSink::RecvPacket, this));
        }
    }

    virtual void StopApplication()
    {
        if (m_socket)
        {
            m_socket->Close();
            m_socket = 0;
        }
    }

    void RecvPacket(Ptr<Socket> socket)
    {
        Ptr<Packet> packet = socket->Recv();
        sinkDroppedPackets[m_nodeId]++;
    }

private:
    Ptr<Socket> m_socket;
    Address m_address;
    uint32_t m_nodeId;
};

// =====================================================
// SVM Classifier
// =====================================================
class SimpleSvmClassifier : public Object
{
public:
    SimpleSvmClassifier()
    {
        w1 = 0.1;
        w2 = 0.3;
        w3 = -1.2;
        w4 = -0.4;
        bias = 0.6;
    }

    bool Predict(double f1, double f2, double f3, double f4)
    {
        double decision = w1*f1 + w2*f2 + w3*f3 + w4*f4 + bias;
        return decision < 0;
    }

private:
    double w1,w2,w3,w4,bias;
};

// =====================================================
// Detection Hub
// =====================================================
class DetectionHub : public Object
{
public:
    DetectionHub(uint32_t hubId, Ptr<SimpleSvmClassifier> clf)
    {
        m_hubId = hubId;
        m_clf = clf;
    }

    void ReceiveReport(uint32_t nodeId, double tx, double rx,
                       double drop, double delay)
    {
        bool mal = m_clf->Predict(tx, rx, drop, delay);
        if (mal)
            localAlerts.insert(nodeId);
    }

    const std::set<uint32_t>& GetAlerts() const { return localAlerts; }

private:
    uint32_t m_hubId;
    Ptr<SimpleSvmClassifier> m_clf;
    std::set<uint32_t> localAlerts;
};

// =====================================================
// Global Coordinator
// =====================================================
class GlobalCoordinator : public Object
{
public:
    GlobalCoordinator(uint32_t numHubs)
    {
        voteCount.resize(10000,0);
    }

    void AddHubAlerts(uint32_t hubId, const std::set<uint32_t>& alerts)
    {
        for (auto n : alerts)
            voteCount[n]++;
    }

    bool IsConfirmedMalicious(uint32_t nodeId)
    {
        return voteCount[nodeId] >= 2;
    }

private:
    std::vector<int> voteCount;
};

// =====================================================
// Reporting Function
// =====================================================
std::vector< Ptr<DetectionHub> > hubs;
Ptr<GlobalCoordinator> coordinator;
AnimationInterface* g_anim;

void ReportToHub(uint32_t nodeId)
{
    uint32_t hubId = nodeId % hubs.size();

    double tx = txPackets[nodeId];
    double rx = rxPackets[nodeId];
    double drop = sinkDroppedPackets[nodeId];
    double delay = (tx == 0 ? 0 : (tx - rx) * 0.005);

    hubs[hubId]->ReceiveReport(nodeId, tx, rx, drop, delay);

    Simulator::Schedule(Seconds(1.0), &ReportToHub, nodeId);
}

// =====================================================
// Global detection loop
// =====================================================
void GlobalDetectAndColor()
{
    for (uint32_t h = 0; h < hubs.size(); ++h)
        coordinator->AddHubAlerts(h, hubs[h]->GetAlerts());

    for (uint32_t i = 0; i < txPackets.size(); ++i)
    {
        if (coordinator->IsConfirmedMalicious(i))
        {
            g_anim->UpdateNodeColor(i, 255, 255, 0);
            g_anim->UpdateNodeDescription(i, "Detected-Malicious");
        }
    }

    Simulator::Schedule(Seconds(2.0), &GlobalDetectAndColor);
}

// =====================================================
// MAIN
// =====================================================
int main(int argc, char *argv[])
{
    uint32_t nNodes = 500;
    uint32_t nMalicious = 50;
    double simTime = 200.0;
    uint32_t nFlows = 200;

    CommandLine cmd;
    cmd.AddValue("nNodes", "Number of total nodes", nNodes);
    cmd.AddValue("nMalicious", "Number of malicious nodes", nMalicious);
    cmd.AddValue("simTime", "Simulation time (s)", simTime);
    cmd.AddValue("nFlows", "Number of flows", nFlows);
    cmd.Parse(argc, argv);

    txPackets.assign(nNodes, 0);
    rxPackets.assign(nNodes, 0);
    sinkDroppedPackets.assign(nNodes, 0);

    NodeContainer nodes;
    nodes.Create(nNodes);

    // Pick malicious nodes
    Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
    uv->SetSeed(12345);
    std::vector<uint32_t> isMalicious(nNodes,0);
    std::set<uint32_t> malSet;
    while(malSet.size()<nMalicious)
        malSet.insert(uv->GetInteger(0,nNodes-1));
    for(auto x:malSet) isMalicious[x]=1;

    // Mobility
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    for(uint32_t i=0;i<nNodes;i++)
    {
        double lane = (i%3);
        double pos = i*5.0;
        positionAlloc->Add(Vector(pos,lane*4.0,0));
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(nodes);

    for(uint32_t i=0;i<nNodes;i++)
    {
        auto mob = nodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mob->SetVelocity(Vector(20+(i%5),0,0));
    }

    // Wifi
    WifiHelper wifi;
    wifi.SetStandard(WIFI_PHY_STANDARD_80211g);
    YansWifiPhyHelper phy = YansWifiPhyHelper::Default();
    YansWifiChannelHelper chan = YansWifiChannelHelper::Default();
    phy.SetChannel(chan.Create());
    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy,mac,nodes);

    // Internet + AODV
    AodvHelper aodv;
    InternetStackHelper net;
    net.SetRoutingHelper(aodv);
    net.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.0.0.0","255.0.0.0");
    Ipv4InterfaceContainer ifaces = ipv4.Assign(devices);

    // Applications
    Ptr<UniformRandomVariable> rnd = CreateObject<UniformRandomVariable>();
    uint16_t port = 8080;

    for(uint32_t f=0;f<nFlows;f++)
    {
        uint32_t src = rnd->GetInteger(0,nNodes-1);
        uint32_t dst = rnd->GetInteger(0,nNodes-1);
        if(src==dst) dst=(dst+1)%nNodes;

        if(isMalicious[dst])
        {
            Ptr<MaliciousSink> ms = CreateObject<MaliciousSink>();
            nodes.Get(dst)->AddApplication(ms);
            ms->Setup(InetSocketAddress(ifaces.GetAddress(dst),port),dst);
            ms->SetStartTime(Seconds(1.0));
            ms->SetStopTime(Seconds(simTime-1.0));
        }
        else
        {
            PacketSinkHelper sink("ns3::UdpSocketFactory",
                InetSocketAddress(Ipv4Address::GetAny(),port));
            auto s = sink.Install(nodes.Get(dst));
            s.Start(Seconds(1.0));
            s.Stop(Seconds(simTime-1.0));
        }

        OnOffHelper onoff("ns3::UdpSocketFactory",
            InetSocketAddress(ifaces.GetAddress(dst),port));
        onoff.SetAttribute("DataRate", StringValue("64kb/s"));
        onoff.SetAttribute("PacketSize", UintegerValue(512));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

        auto c = onoff.Install(nodes.Get(src));
        c.Start(Seconds(2.0+0.01*f));
        c.Stop(Seconds(simTime-2.0));
    }

    // ==========================
    // Multi-Hub IDS initialization
    // ==========================
    uint32_t numHubs=5;
    hubs.resize(numHubs);
    Ptr<SimpleSvmClassifier> clf = CreateObject<SimpleSvmClassifier>();
    for(uint32_t h=0;h<numHubs;h++)
        hubs[h]=CreateObject<DetectionHub>(h,clf);
    coordinator = CreateObject<GlobalCoordinator>(numHubs);

    // Start reporting
    for(uint32_t i=0;i<nNodes;i++)
        Simulator::Schedule(Seconds(5.0), &ReportToHub, i);

    // NetAnim
    AnimationInterface anim("vanet_blackhole.xml");
    g_anim = &anim;

    for(uint32_t i=0;i<nNodes;i++)
    {
        if(isMalicious[i]){
            anim.UpdateNodeColor(i,255,0,0);
            anim.UpdateNodeDescription(i,"Malicious");
        } else {
            anim.UpdateNodeColor(i,0,0,255);
            anim.UpdateNodeDescription(i,"Normal");
        }
    }

    // start global detection loop
    Simulator::Schedule(Seconds(15.0), &GlobalDetectAndColor);

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    WriteCsv("vanet_features.csv", nNodes, isMalicious);
    Simulator::Destroy();

    return 0;
}
