//
// VEYRA - vehicle (sensor node) application. See VeyraVehicleApp.h.
//
package veyra;

import org.car2x.veins.modules.application.ieee80211p.DemoBaseApplLayer;

simple VeyraVehicleApp extends DemoBaseApplLayer
{
    parameters:
        @class(veyra::VeyraVehicleApp);
        int maxVehicles = default(20);        // only the first N cars SUMO inserts take part (-1 = all); match gateway_service.py --vehicles
        int handshakeBytes = default(1125B) @unit(B);   // C1 || C2 on the air (ML-KEM-768)
        int readingBytes = default(150B) @unit(B);      // C_ij || tso || PD_ij
        double readingInterval = default(1s) @unit(s);
        double handshakeTimeout = default(1s) @unit(s); // retry if no C3 by then
        double beaconTimeout = default(2.5s) @unit(s);  // RSU counts as out of range after this long without a beacon
        string handoverPolicy = default("rssi");       // "rssi" or "distance"
        double minRssi @unit(dBm) = default(-89dBm);    // rssi: do not handshake with an RSU weaker than this
        double handoverHysteresis @unit(dB) = default(3dB); // rssi: switch only to an RSU this much stronger
        double handoverMargin = default(50m) @unit(m);  // distance: switch only if the new RSU is this much closer
        int compromisedIndex = default(3);              // node[N] lies about its speed (-1 = nobody)
        double fakeSpeedKmh = default(250);             // reports fakeSpeedKmh + uniform(0, 20)
        double attackStart = default(20s) @unit(s);     // seconds after that car enters the map

        @signal[handshakeLatency](type=simtime_t);
        @statistic[handshakeLatency](title="handshake latency (successful request -> C3 received)"; unit=s; record=vector,stats,histogram);
        @signal[timeToSession](type=simtime_t);
        @statistic[timeToSession](title="time to session (first request -> C3 received, including retries)"; unit=s; record=vector,stats,histogram);
        @signal[readingSent](type=long);
        @statistic[readingSent](title="readings sent"; record=count);
}
