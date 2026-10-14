//
// VEYRA - RSU application: bridge to gateway_service.py. See VeyraRsuApp.h.
//
package veyra;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple VeyraRsuApp extends DemoBaseApplLayer
{
    parameters:
        @class(veyra::VeyraRsuApp);
        string gatewayHost = default("127.0.0.1");
        int firstGatewayPort = default(9001);   // rsu[j] uses firstGatewayPort + j
        int gatewayPort = default(-1);          // or set one explicitly
        int beaconBytes = default(100B) @unit(B);
        int handshakeRespBytes = default(120B) @unit(B);  // C3; the service's bytes_down overrides it
        double rsuBeaconInterval = default(1s) @unit(s);
        double tickInterval = default(1s) @unit(s);      // publish + finalise once per second
        bool modelGatewayCpu = default(true);   // work waits while the gateway is busy (queue_ms)
        string resultsDir = default("../../results");    // relative to the simulations folder
        bool shutdownService = default(true);   // stop gateway_service.py at the end of the run

        @signal[airDelay](type=simtime_t);
        @statistic[airDelay](title="802.11p delay (sent -> received at RSU)"; unit=s; record=vector,stats,histogram);
        @signal[gatewayQueueDelay](type=simtime_t);
        @statistic[gatewayQueueDelay](title="wait for the gateway CPU"; unit=s; record=vector,stats);
        @signal[readingEndToEnd](type=double);
        @statistic[readingEndToEnd](title="reading end-to-end (seal + air + queue + Alg. 3)"; unit=s; record=vector,stats,histogram);
        @signal[handshakeProc](type=double);
        @statistic[handshakeProc](title="handshake processing (Alg. 2)"; unit=s; record=stats);
        @signal[tickProc](type=double);
        @statistic[tickProc](title="tick processing (Eq. 6-7, Alg. 4-5)"; unit=s; record=vector,stats);
}
