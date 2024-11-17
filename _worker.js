var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// _worker.js
import { connect } from "cloudflare:sockets";
var userID = "d342d11e-d424-4583-b36e-524ab1f0afa4";
var \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35s = ["178.128.91.137"];
var \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35 = \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35s[Math.floor(Math.random() * \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35s.length)];
var dohURL = "https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=";
if (!isValidUUID(userID)) {
  throw new Error("uuid is invalid");
}
var worker_default = {
  /**
   * @param {import("@cloudflare/workers-types").Request} request
   * @param {{UUID: string, พร็อกซีไอพี: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
   * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      userID = env.UUID || userID;
      \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35 = env.PROXYIP || \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35;
      dohURL = env.DNS_RESOLVER_URL || dohURL;
      let userID_Path = userID;
      if (userID.includes(",")) {
        userID_Path = userID.split(",")[0];
      }
      const upgradeHeader = request.headers.get("Upgrade");
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/cf`: {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8"
              }
            });
          }
          case `/${userID_Path}`:
            {
              const \u0E27\u0E40\u0E25\u0E2AConfig = get\u0E27\u0E40\u0E25\u0E2AConfig(userID, request.headers.get("Host"));
              return new Response(`${\u0E27\u0E40\u0E25\u0E2AConfig}`, {
                status: 200,
                headers: {
                  "Content-Type": "text/html; charset=utf-8"
                }
              });
            }
            ;
          case `/sub/${userID_Path}`:
            {
              const url2 = new URL(request.url);
              const searchParams = url2.searchParams;
              const \u0E27\u0E40\u0E25\u0E2ASubConfig = \u0E2A\u0E23\u0E49\u0E32\u0E07\u0E27\u0E40\u0E25\u0E2ASub(userID, request.headers.get("Host"));
              return new Response(btoa(\u0E27\u0E40\u0E25\u0E2ASubConfig), {
                status: 200,
                headers: {
                  "Content-Type": "text/plain;charset=utf-8"
                }
              });
            }
            ;
          case `/bestip/${userID_Path}`:
            {
              const headers = request.headers;
              const url2 = `https://sub.xf.free.hr/auto?host=${request.headers.get("Host")}&uuid=${userID}&path=/`;
              const bestSubConfig = await fetch(url2, { headers });
              return bestSubConfig;
            }
            ;
          default:
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual"
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Redirects to ${randomHostname} are not allowed.`, {
                status: 403,
                statusText: "Forbidden"
              });
            }
            return proxyResponse;
        }
      } else {
        return await \u0E27\u0E40\u0E25\u0E2AOverWSHandler(request);
      }
    } catch (err) {
      let e = err;
      return new Response(e.toString());
    }
  }
};
async function uuid_validator(request) {
  const hostname = request.headers.get("Host");
  const currentDate = /* @__PURE__ */ new Date();
  const subdomain = hostname.split(".")[0];
  const year = currentDate.getFullYear();
  const month = String(currentDate.getMonth() + 1).padStart(2, "0");
  const day = String(currentDate.getDate()).padStart(2, "0");
  const formattedDate = `${year}-${month}-${day}`;
  const hashHex = await hashHex_f(subdomain);
  console.log(hashHex, subdomain, formattedDate);
}
__name(uuid_validator, "uuid_validator");
async function hashHex_f(string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(string);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return hashHex;
}
__name(hashHex_f, "hashHex_f");
async function \u0E27\u0E40\u0E25\u0E2AOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = "";
  let portWithRandomLog = "";
  let currentDate = /* @__PURE__ */ new Date();
  const log = /* @__PURE__ */ __name((info, event) => {
    console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || "");
  }, "log");
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = {
    value: null
  };
  let udpStreamWrite = null;
  let isDns = false;
  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk, controller) {
      if (isDns && udpStreamWrite) {
        return udpStreamWrite(chunk);
      }
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      const {
        hasError,
        message,
        portRemote = 443,
        addressRemote = "",
        rawDataIndex,
        \u0E27\u0E40\u0E25\u0E2AVersion = new Uint8Array([0, 0]),
        isUDP
      } = process\u0E27\u0E40\u0E25\u0E2AHeader(chunk, userID);
      address = addressRemote;
      portWithRandomLog = `${portRemote} ${isUDP ? "udp" : "tcp"} `;
      if (hasError) {
        throw new Error(message);
      }
      if (isUDP && portRemote !== 53) {
        throw new Error("UDP proxy only enabled for DNS which is port 53");
      }
      if (isUDP && portRemote === 53) {
        isDns = true;
      }
      const \u0E27\u0E40\u0E25\u0E2AResponseHeader = new Uint8Array([\u0E27\u0E40\u0E25\u0E2AVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      if (isDns) {
        const { write } = await handleUDPOutBound(webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, log);
        udpStreamWrite = write;
        udpStreamWrite(rawClientData);
        return;
      }
      handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, log);
    },
    close() {
      log(`readableWebSocketStream is close`);
    },
    abort(reason) {
      log(`readableWebSocketStream is abort`, JSON.stringify(reason));
    }
  })).catch((err) => {
    log("readableWebSocketStream pipeTo error", err);
  });
  return new Response(null, {
    status: 101,
    webSocket: client
  });
}
__name(\u0E27\u0E40\u0E25\u0E2AOverWSHandler, "\u0E27\u0E40\u0E25\u0E2AOverWSHandler");
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket2 = connect({
      hostname: address,
      port
    });
    remoteSocket.value = tcpSocket2;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket2.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket2;
  }
  __name(connectAndWrite, "connectAndWrite");
  async function retry() {
    const tcpSocket2 = await connectAndWrite(\u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35 || addressRemote, portRemote);
    tcpSocket2.closed.catch((error) => {
      console.log("retry tcpSocket closed error", error);
    }).finally(() => {
      safeCloseWebSocket(webSocket);
    });
    remoteSocketToWS(tcpSocket2, webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, null, log);
  }
  __name(retry, "retry");
  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, retry, log);
}
__name(handleTCPOutBound, "handleTCPOutBound");
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    pull(controller) {
    },
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
  return stream;
}
__name(makeReadableWebSocketStream, "makeReadableWebSocketStream");
function process\u0E27\u0E40\u0E25\u0E2AHeader(\u0E27\u0E40\u0E25\u0E2ABuffer, userID2) {
  if (\u0E27\u0E40\u0E25\u0E2ABuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "invalid data"
    };
  }
  const version = new Uint8Array(\u0E27\u0E40\u0E25\u0E2ABuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  const slicedBuffer = new Uint8Array(\u0E27\u0E40\u0E25\u0E2ABuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);
  const uuids = userID2.includes(",") ? userID2.split(",") : [userID2];
  isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();
  console.log(`userID: ${slicedBufferString}`);
  if (!isValidUser) {
    return {
      hasError: true,
      message: "invalid user"
    };
  }
  const optLength = new Uint8Array(\u0E27\u0E40\u0E25\u0E2ABuffer.slice(17, 18))[0];
  const command = new Uint8Array(
    \u0E27\u0E40\u0E25\u0E2ABuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];
  if (command === 1) {
    isUDP = false;
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = \u0E27\u0E40\u0E25\u0E2ABuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(
    \u0E27\u0E40\u0E25\u0E2ABuffer.slice(addressIndex, addressIndex + 1)
  );
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(
        \u0E27\u0E40\u0E25\u0E2ABuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      ).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(
        \u0E27\u0E40\u0E25\u0E2ABuffer.slice(addressValueIndex, addressValueIndex + 1)
      )[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        \u0E27\u0E40\u0E25\u0E2ABuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(
        \u0E27\u0E40\u0E25\u0E2ABuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`
    };
  }
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    \u0E27\u0E40\u0E25\u0E2AVersion: version,
    isUDP
  };
}
__name(process\u0E27\u0E40\u0E25\u0E2AHeader, "process\u0E27\u0E40\u0E25\u0E2AHeader");
async function remoteSocketToWS(remoteSocket, webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, retry, log) {
  let remoteChunkCount = 0;
  let chunks = [];
  let \u0E27\u0E40\u0E25\u0E2AHeader = \u0E27\u0E40\u0E25\u0E2AResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(
    new WritableStream({
      start() {
      },
      /**
       * 
       * @param {Uint8Array} chunk 
       * @param {*} controller 
       */
      async write(chunk, controller) {
        hasIncomingData = true;
        remoteChunkCount++;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error(
            "webSocket.readyState is not open, maybe close"
          );
        }
        if (\u0E27\u0E40\u0E25\u0E2AHeader) {
          webSocket.send(await new Blob([\u0E27\u0E40\u0E25\u0E2AHeader, chunk]).arrayBuffer());
          \u0E27\u0E40\u0E25\u0E2AHeader = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() {
        log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
      },
      abort(reason) {
        console.error(`remoteConnection!.readable abort`, reason);
      }
    })
  ).catch((error) => {
    console.error(
      `remoteSocketToWS has exception `,
      error.stack || error
    );
    safeCloseWebSocket(webSocket);
  });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}
__name(remoteSocketToWS, "remoteSocketToWS");
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { earlyData: null, error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}
__name(base64ToArrayBuffer, "base64ToArrayBuffer");
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}
__name(isValidUUID, "isValidUUID");
var WS_READY_STATE_OPEN = 1;
var WS_READY_STATE_CLOSING = 2;
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}
__name(safeCloseWebSocket, "safeCloseWebSocket");
var byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
__name(unsafeStringify, "unsafeStringify");
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
__name(stringify, "stringify");
async function handleUDPOutBound(webSocket, \u0E27\u0E40\u0E25\u0E2AResponseHeader, log) {
  let is\u0E27\u0E40\u0E25\u0E2AHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {
    },
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPakcetLength)
        );
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {
    }
  });
  transformStream.readable.pipeTo(new WritableStream({
    async write(chunk) {
      const resp = await fetch(
        dohURL,
        // dns server url
        {
          method: "POST",
          headers: {
            "content-type": "application/dns-message"
          },
          body: chunk
        }
      );
      const dnsQueryResult = await resp.arrayBuffer();
      const udpSize = dnsQueryResult.byteLength;
      const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);
      if (webSocket.readyState === WS_READY_STATE_OPEN) {
        log(`doh success and dns message length is ${udpSize}`);
        if (is\u0E27\u0E40\u0E25\u0E2AHeaderSent) {
          webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
        } else {
          webSocket.send(await new Blob([\u0E27\u0E40\u0E25\u0E2AResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
          is\u0E27\u0E40\u0E25\u0E2AHeaderSent = true;
        }
      }
    }
  })).catch((error) => {
    log("dns udp has error" + error);
  });
  const writer = transformStream.writable.getWriter();
  return {
    /**
     * 
     * @param {Uint8Array} chunk 
     */
    write(chunk) {
      writer.write(chunk);
    }
  };
}
__name(handleUDPOutBound, "handleUDPOutBound");
var at = "QA==";
var pt = "dmxlc3M=";
var ed = "RUR0dW5uZWw=";
function get\u0E27\u0E40\u0E25\u0E2AConfig(userIDs, hostName) {
  const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2Faryo#${hostName}`;
  const hashSeparator = "################################################################";
  const userIDArray = userIDs.split(",");
  const output = userIDArray.map((userID2) => {
    const \u0E27\u0E40\u0E25\u0E2AMain = atob(pt) + "://" + userID2 + atob(at) + hostName + commonUrlPart;
    const \u0E27\u0E40\u0E25\u0E2ASec = atob(pt) + "://" + userID2 + atob(at) + \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35 + commonUrlPart;
    return `<h2>UUID: ${userID2}</h2>${hashSeparator}
v2ray default ip
---------------------------------------------------------------
${\u0E27\u0E40\u0E25\u0E2AMain}
<button onclick='copyToClipboard("${\u0E27\u0E40\u0E25\u0E2AMain}")'><i class="fa fa-clipboard"></i> Copy \u0E27\u0E40\u0E25\u0E2AMain</button>
---------------------------------------------------------------
v2ray with bestip
---------------------------------------------------------------
${\u0E27\u0E40\u0E25\u0E2ASec}
<button onclick='copyToClipboard("${\u0E27\u0E40\u0E25\u0E2ASec}")'><i class="fa fa-clipboard"></i> Copy \u0E27\u0E40\u0E25\u0E2ASec</button>
---------------------------------------------------------------`;
  }).join("\n");
  const sublink = `https://${hostName}/sub/${userIDArray[0]}?format=clash`;
  const subbestip = `https://${hostName}/bestip/${userIDArray[0]}`;
  const clash_link = `https://api.v1.mk/sub?target=clash&url=${encodeURIComponent(sublink)}&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
  const header = `
<p align='center'><img src='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' alt='\u56FE\u7247\u63CF\u8FF0' style='margin-bottom: -50px;'>
<b style='font-size: 15px;'>Welcome! This function generates configuration for \u0E27\u0E40\u0E25\u0E2A protocol. If you found this useful, please check our GitHub project for more:</b>
<b style='font-size: 15px;'>\u6B22\u8FCE\uFF01\u8FD9\u662F\u751F\u6210 \u0E27\u0E40\u0E25\u0E2A \u534F\u8BAE\u7684\u914D\u7F6E\u3002\u5982\u679C\u60A8\u53D1\u73B0\u8FD9\u4E2A\u9879\u76EE\u5F88\u597D\u7528\uFF0C\u8BF7\u67E5\u770B\u6211\u4EEC\u7684 GitHub \u9879\u76EE\u7ED9\u6211\u4E00\u4E2Astar\uFF1A</b>
<a href='https://github.com/3Kmfi6HP/EDtunnel' target='_blank'>EDtunnel - https://github.com/3Kmfi6HP/EDtunnel</a>
<iframe src='https://ghbtns.com/github-btn.html?user=USERNAME&repo=REPOSITORY&type=star&count=true&size=large' frameborder='0' scrolling='0' width='170' height='30' title='GitHub'></iframe>
<a href='//${hostName}/sub/${userIDArray[0]}' target='_blank'>\u0E27\u0E40\u0E25\u0E2A \u8282\u70B9\u8BA2\u9605\u8FDE\u63A5</a>
<a href='clash://install-config?url=${encodeURIComponent(`https://${hostName}/sub/${userIDArray[0]}?format=clash`)}}' target='_blank'>Clash for Windows \u8282\u70B9\u8BA2\u9605\u8FDE\u63A5</a>
<a href='${clash_link}' target='_blank'>Clash \u8282\u70B9\u8BA2\u9605\u8FDE\u63A5</a>
<a href='${subbestip}' target='_blank'>\u4F18\u9009IP\u81EA\u52A8\u8282\u70B9\u8BA2\u9605</a>
<a href='clash://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>Clash\u4F18\u9009IP\u81EA\u52A8</a>
<a href='sing-box://import-remote-profile?url=${encodeURIComponent(subbestip)}' target='_blank'>singbox\u4F18\u9009IP\u81EA\u52A8</a>
<a href='sn://subscription?url=${encodeURIComponent(subbestip)}' target='_blank'>nekobox\u4F18\u9009IP\u81EA\u52A8</a>
<a href='v2rayng://install-config?url=${encodeURIComponent(subbestip)}' target='_blank'>v2rayNG\u4F18\u9009IP\u81EA\u52A8</a></p>`;
  const htmlHead = `
  <head>
	<title>EDtunnel: \u0E27\u0E40\u0E25\u0E2A configuration</title>
	<meta name='description' content='This is a tool for generating \u0E27\u0E40\u0E25\u0E2A protocol configurations. Give us a star on GitHub https://github.com/3Kmfi6HP/EDtunnel if you found it useful!'>
	<meta name='keywords' content='EDtunnel, cloudflare pages, cloudflare worker, severless'>
	<meta name='viewport' content='width=device-width, initial-scale=1'>
	<meta property='og:site_name' content='EDtunnel: \u0E27\u0E40\u0E25\u0E2A configuration' />
	<meta property='og:type' content='website' />
	<meta property='og:title' content='EDtunnel - \u0E27\u0E40\u0E25\u0E2A configuration and subscribe output' />
	<meta property='og:description' content='Use cloudflare pages and worker severless to implement \u0E27\u0E40\u0E25\u0E2A protocol' />
	<meta property='og:url' content='https://${hostName}/' />
	<meta property='og:image' content='https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`\u0E27\u0E40\u0E25\u0E2A://${userIDs.split(",")[0]}@${hostName}${commonUrlPart}`)}' />
	<meta name='twitter:card' content='summary_large_image' />
	<meta name='twitter:title' content='EDtunnel - \u0E27\u0E40\u0E25\u0E2A configuration and subscribe output' />
	<meta name='twitter:description' content='Use cloudflare pages and worker severless to implement \u0E27\u0E40\u0E25\u0E2A protocol' />
	<meta name='twitter:url' content='https://${hostName}/' />
	<meta name='twitter:image' content='https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky' />
	<meta property='og:image:width' content='1500' />
	<meta property='og:image:height' content='1500' />

	<style>
	body {
	  font-family: Arial, sans-serif;
	  background-color: #f0f0f0;
	  color: #333;
	  padding: 10px;
	}

	a {
	  color: #1a0dab;
	  text-decoration: none;
	}
	img {
	  max-width: 100%;
	  height: auto;
	}

	pre {
	  white-space: pre-wrap;
	  word-wrap: break-word;
	  background-color: #fff;
	  border: 1px solid #ddd;
	  padding: 15px;
	  margin: 10px 0;
	}
	/* Dark mode */
	@media (prefers-color-scheme: dark) {
	  body {
		background-color: #333;
		color: #f0f0f0;
	  }

	  a {
		color: #9db4ff;
	  }

	  pre {
		background-color: #282a36;
		border-color: #6272a4;
	  }
	}
	</style>

	<!-- Add FontAwesome library -->
	<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css'>
  </head>
  `;
  return `
  <html>
  ${htmlHead}
  <body>
  <pre style='background-color: transparent; border: none;'>${header}</pre>
  <pre>${output}</pre>
  </body>
  <script>
	function copyToClipboard(text) {
	  navigator.clipboard.writeText(text)
		.then(() => {
		  alert("Copied to clipboard");
		})
		.catch((err) => {
		  console.error("Failed to copy to clipboard:", err);
		});
	}
  <\/script>
  </html>`;
}
__name(get\u0E27\u0E40\u0E25\u0E2AConfig, "get\u0E27\u0E40\u0E25\u0E2AConfig");
var \u0E40\u0E0B\u0E47\u0E15\u0E1E\u0E2D\u0E23\u0E4C\u0E15Http = /* @__PURE__ */ new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);
var \u0E40\u0E0B\u0E47\u0E15\u0E1E\u0E2D\u0E23\u0E4C\u0E15Https = /* @__PURE__ */ new Set([443, 8443, 2053, 2096, 2087, 2083]);
function \u0E2A\u0E23\u0E49\u0E32\u0E07\u0E27\u0E40\u0E25\u0E2ASub(\u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49_\u0E40\u0E2A\u0E49\u0E19\u0E17\u0E32\u0E07, \u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C) {
  const \u0E2D\u0E32\u0E23\u0E4C\u0E40\u0E23\u0E22\u0E4C\u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49 = \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49_\u0E40\u0E2A\u0E49\u0E19\u0E17\u0E32\u0E07.includes(",") ? \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49_\u0E40\u0E2A\u0E49\u0E19\u0E17\u0E32\u0E07.split(",") : [\u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49_\u0E40\u0E2A\u0E49\u0E19\u0E17\u0E32\u0E07];
  const \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttp = `?encryption=none&security=none&fp=random&type=ws&host=${\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C}&path=%2Faryo#`;
  const \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttps = `?encryption=none&security=tls&sni=${\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C}&fp=random&type=ws&host=${\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C}&path=%2Faryo#`;
  const \u0E1C\u0E25\u0E25\u0E31\u0E1E\u0E18\u0E4C = \u0E2D\u0E32\u0E23\u0E4C\u0E40\u0E23\u0E22\u0E4C\u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49.flatMap((\u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49) => {
    const \u0E01\u0E32\u0E23\u0E01\u0E33\u0E2B\u0E19\u0E14\u0E04\u0E48\u0E32Http = Array.from(\u0E40\u0E0B\u0E47\u0E15\u0E1E\u0E2D\u0E23\u0E4C\u0E15Http).flatMap((\u0E1E\u0E2D\u0E23\u0E4C\u0E15) => {
      if (!\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C.includes("pages.dev")) {
        const \u0E2A\u0E48\u0E27\u0E19Url = `${\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C}-HTTP-${\u0E1E\u0E2D\u0E23\u0E4C\u0E15}`;
        const \u0E27\u0E40\u0E25\u0E2A\u0E2B\u0E25\u0E31\u0E01Http = atob(pt) + "://" + \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49 + atob(at) + \u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C + ":" + \u0E1E\u0E2D\u0E23\u0E4C\u0E15 + \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttp + \u0E2A\u0E48\u0E27\u0E19Url;
        return \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35s.flatMap((\u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352) => {
          const \u0E27\u0E40\u0E25\u0E2A\u0E23\u0E2D\u0E07Http = atob(pt) + "://" + \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49 + atob(at) + \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352 + ":" + \u0E1E\u0E2D\u0E23\u0E4C\u0E15 + \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttp + \u0E2A\u0E48\u0E27\u0E19Url + "-" + \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352 + "-" + atob(ed);
          return [\u0E27\u0E40\u0E25\u0E2A\u0E2B\u0E25\u0E31\u0E01Http, \u0E27\u0E40\u0E25\u0E2A\u0E23\u0E2D\u0E07Http];
        });
      }
      return [];
    });
    const \u0E01\u0E32\u0E23\u0E01\u0E33\u0E2B\u0E19\u0E14\u0E04\u0E48\u0E32Https = Array.from(\u0E40\u0E0B\u0E47\u0E15\u0E1E\u0E2D\u0E23\u0E4C\u0E15Https).flatMap((\u0E1E\u0E2D\u0E23\u0E4C\u0E15) => {
      const \u0E2A\u0E48\u0E27\u0E19Url = `${\u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C}-HTTPS-${\u0E1E\u0E2D\u0E23\u0E4C\u0E15}`;
      const \u0E27\u0E40\u0E25\u0E2A\u0E2B\u0E25\u0E31\u0E01Https = atob(pt) + "://" + \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49 + atob(at) + \u0E0A\u0E37\u0E48\u0E2D\u0E42\u0E2E\u0E2A\u0E15\u0E4C + ":" + \u0E1E\u0E2D\u0E23\u0E4C\u0E15 + \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttps + \u0E2A\u0E48\u0E27\u0E19Url;
      return \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E35s.flatMap((\u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352) => {
        const \u0E27\u0E40\u0E25\u0E2A\u0E23\u0E2D\u0E07Https = atob(pt) + "://" + \u0E44\u0E2D\u0E14\u0E35\u0E1C\u0E39\u0E49\u0E43\u0E0A\u0E49 + atob(at) + \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352 + ":" + \u0E1E\u0E2D\u0E23\u0E4C\u0E15 + \u0E2A\u0E48\u0E27\u0E19Url\u0E17\u0E31\u0E48\u0E27\u0E44\u0E1BHttps + \u0E2A\u0E48\u0E27\u0E19Url + "-" + \u0E1E\u0E23\u0E47\u0E2D\u0E01\u0E0B\u0E35\u0E44\u0E2D\u0E1E\u0E352 + "-" + atob(ed);
        return [\u0E27\u0E40\u0E25\u0E2A\u0E2B\u0E25\u0E31\u0E01Https, \u0E27\u0E40\u0E25\u0E2A\u0E23\u0E2D\u0E07Https];
      });
    });
    return [...\u0E01\u0E32\u0E23\u0E01\u0E33\u0E2B\u0E19\u0E14\u0E04\u0E48\u0E32Http, ...\u0E01\u0E32\u0E23\u0E01\u0E33\u0E2B\u0E19\u0E14\u0E04\u0E48\u0E32Https];
  });
  return \u0E1C\u0E25\u0E25\u0E31\u0E1E\u0E18\u0E4C.join("\n");
}
__name(\u0E2A\u0E23\u0E49\u0E32\u0E07\u0E27\u0E40\u0E25\u0E2ASub, "\u0E2A\u0E23\u0E49\u0E32\u0E07\u0E27\u0E40\u0E25\u0E2ASub");
var cn_hostnames = [
  "weibo.com",
  // Weibo - A popular social media platform
  "www.baidu.com",
  // Baidu - The largest search engine in China
  "www.qq.com",
  // QQ - A widely used instant messaging platform
  "www.taobao.com",
  // Taobao - An e-commerce website owned by Alibaba Group
  "www.jd.com",
  // JD.com - One of the largest online retailers in China
  "www.sina.com.cn",
  // Sina - A Chinese online media company
  "www.sohu.com",
  // Sohu - A Chinese internet service provider
  "www.tmall.com",
  // Tmall - An online retail platform owned by Alibaba Group
  "www.163.com",
  // NetEase Mail - One of the major email providers in China
  "www.zhihu.com",
  // Zhihu - A popular question-and-answer website
  "www.youku.com",
  // Youku - A Chinese video sharing platform
  "www.xinhuanet.com",
  // Xinhua News Agency - Official news agency of China
  "www.douban.com",
  // Douban - A Chinese social networking service
  "www.meituan.com",
  // Meituan - A Chinese group buying website for local services
  "www.toutiao.com",
  // Toutiao - A news and information content platform
  "www.ifeng.com",
  // iFeng - A popular news website in China
  "www.autohome.com.cn",
  // Autohome - A leading Chinese automobile online platform
  "www.360.cn",
  // 360 - A Chinese internet security company
  "www.douyin.com",
  // Douyin - A Chinese short video platform
  "www.kuaidi100.com",
  // Kuaidi100 - A Chinese express delivery tracking service
  "www.wechat.com",
  // WeChat - A popular messaging and social media app
  "www.csdn.net",
  // CSDN - A Chinese technology community website
  "www.imgo.tv",
  // ImgoTV - A Chinese live streaming platform
  "www.aliyun.com",
  // Alibaba Cloud - A Chinese cloud computing company
  "www.eyny.com",
  // Eyny - A Chinese multimedia resource-sharing website
  "www.mgtv.com",
  // MGTV - A Chinese online video platform
  "www.xunlei.com",
  // Xunlei - A Chinese download manager and torrent client
  "www.hao123.com",
  // Hao123 - A Chinese web directory service
  "www.bilibili.com",
  // Bilibili - A Chinese video sharing and streaming platform
  "www.youth.cn",
  // Youth.cn - A China Youth Daily news portal
  "www.hupu.com",
  // Hupu - A Chinese sports community and forum
  "www.youzu.com",
  // Youzu Interactive - A Chinese game developer and publisher
  "www.panda.tv",
  // Panda TV - A Chinese live streaming platform
  "www.tudou.com",
  // Tudou - A Chinese video-sharing website
  "www.zol.com.cn",
  // ZOL - A Chinese electronics and gadgets website
  "www.toutiao.io",
  // Toutiao - A news and information app
  "www.tiktok.com",
  // TikTok - A Chinese short-form video app
  "www.netease.com",
  // NetEase - A Chinese internet technology company
  "www.cnki.net",
  // CNKI - China National Knowledge Infrastructure, an information aggregator
  "www.zhibo8.cc",
  // Zhibo8 - A website providing live sports streams
  "www.zhangzishi.cc",
  // Zhangzishi - Personal website of Zhang Zishi, a public intellectual in China
  "www.xueqiu.com",
  // Xueqiu - A Chinese online social platform for investors and traders
  "www.qqgongyi.com",
  // QQ Gongyi - Tencent's charitable foundation platform
  "www.ximalaya.com",
  // Ximalaya - A Chinese online audio platform
  "www.dianping.com",
  // Dianping - A Chinese online platform for finding and reviewing local businesses
  "www.suning.com",
  // Suning - A leading Chinese online retailer
  "www.zhaopin.com",
  // Zhaopin - A Chinese job recruitment platform
  "www.jianshu.com",
  // Jianshu - A Chinese online writing platform
  "www.mafengwo.cn",
  // Mafengwo - A Chinese travel information sharing platform
  "www.51cto.com",
  // 51CTO - A Chinese IT technical community website
  "www.qidian.com",
  // Qidian - A Chinese web novel platform
  "www.ctrip.com",
  // Ctrip - A Chinese travel services provider
  "www.pconline.com.cn",
  // PConline - A Chinese technology news and review website
  "www.cnzz.com",
  // CNZZ - A Chinese web analytics service provider
  "www.telegraph.co.uk",
  // The Telegraph - A British newspaper website	
  "www.ynet.com",
  // Ynet - A Chinese news portal
  "www.ted.com",
  // TED - A platform for ideas worth spreading
  "www.renren.com",
  // Renren - A Chinese social networking service
  "www.pptv.com",
  // PPTV - A Chinese online video streaming platform
  "www.liepin.com",
  // Liepin - A Chinese online recruitment website
  "www.881903.com",
  // 881903 - A Hong Kong radio station website
  "www.aipai.com",
  // Aipai - A Chinese online video sharing platform
  "www.ttpaihang.com",
  // Ttpaihang - A Chinese celebrity popularity ranking website
  "www.quyaoya.com",
  // Quyaoya - A Chinese online ticketing platform
  "www.91.com",
  // 91.com - A Chinese software download website
  "www.dianyou.cn",
  // Dianyou - A Chinese game information website
  "www.tmtpost.com",
  // TMTPost - A Chinese technology media platform
  "www.douban.com",
  // Douban - A Chinese social networking service
  "www.guancha.cn",
  // Guancha - A Chinese news and commentary website
  "www.so.com",
  // So.com - A Chinese search engine
  "www.58.com",
  // 58.com - A Chinese classified advertising website
  "www.cnblogs.com",
  // Cnblogs - A Chinese technology blog community
  "www.cntv.cn",
  // CCTV - China Central Television official website
  "www.secoo.com"
  // Secoo - A Chinese luxury e-commerce platform
];
export {
  worker_default as default,
  hashHex_f,
  uuid_validator
};
//# sourceMappingURL=_worker.js.map
