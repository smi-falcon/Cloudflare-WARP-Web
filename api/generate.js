import { x25519 } from '@noble/curves/ed25519';

const DNS_MAP = {
  '1': { v4: ['1.1.1.1', '1.0.0.1'], v6: ['2606:4700:4700::1111', '2606:4700:4700::1001'] },
  '2': { v4: ['8.8.8.8', '8.8.4.4'], v6: ['2001:4860:4860::8888', '2001:4860:4860::8844'] },
  '3': { v4: ['9.9.9.9', '9.9.9.10'], v6: ['2620:fe::fe', '2620:fe::9'] },
  '4': { v4: ['94.140.14.14', '94.140.15.15'], v6: ['2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff'] },
  '5': { v4: ['83.220.169.155', '212.109.195.93'], v6: [] },
  '6': { v4: ['111.88.96.54', '111.88.96.55'], v6: ['2a00:ab00:1233:26::50', '2a00:ab00:1233:26::51'] },
  '7': { v4: ['217.60.245.219', '217.60.245.233'], v6: [] }
};

const ALLOWED_LAN = '1.0.0.0/8, 2.0.0.0/7, 4.0.0.0/6, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/3, 96.0.0.0/4, 112.0.0.0/5, 120.0.0.0/6, 124.0.0.0/7, 126.0.0.0/8, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/8, 169.0.0.0/9, 169.128.0.0/10, 169.192.0.0/11, 169.224.0.0/12, 169.240.0.0/13, 169.248.0.0/14, 169.252.0.0/15, 169.255.0.0/16, 170.0.0.0/7, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 224.0.0.0/4, ::/1, 8000::/2, c000::/3, e000::/4, f000::/5, f800::/6, fe00::/9, fec0::/10, ff00::/8';

const DEFAULT_I1 = '<b 0xc2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>';

function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function generateKeypair() {
  const privBytes = x25519.utils.randomPrivateKey();
  const pubBytes = x25519.getPublicKey(privBytes);
  return { priv: bytesToBase64(privBytes), pub: bytesToBase64(pubBytes) };
}

async function generateCustomI1(domain) {
  let seed = domain;
  let result = '';
  for (let i = 0; i < 16; i++) {
    const buf = new TextEncoder().encode(seed);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const arr = Array.from(new Uint8Array(hash));
    seed = arr.map(b => b.toString(16).padStart(2, '0')).join('');
    result += seed;
  }
  return `<b 0x${result}>`;
}

async function apiRequest(method, path, token, body) {
  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'okhttp/3.12.1'
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);
  const res = await fetch(`https://api.cloudflareclient.com/v0i1909051800${path}`, options);
  return res.json();
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  try {
    const {
      dnsChoice = '1',
      routing = 'all',
      jcChoice = '4',
      jcCustom,
      mtu = 1280,
      endpointChoice = '1',
      ipv6 = true,
      keepaliveOn = true,
      keepaliveSec = 25,
      customI1 = false,
      i1Domain = ''
    } = req.body;

    let JC, JMIN, JMAX;
    switch (jcChoice) {
      case '1': JC = 3; JMIN = 10; JMAX = 30; break;
      case '2': JC = 4; JMIN = 40; JMAX = 70; break;
      case '3': JC = 6; JMIN = 70; JMAX = 100; break;
      case '5':
        JC = parseInt(jcCustom?.jc, 10) || 120;
        JMIN = parseInt(jcCustom?.jmin, 10) || 23;
        JMAX = parseInt(jcCustom?.jmax, 10) || 911;
        break;
      default: JC = 120; JMIN = 23; JMAX = 911;
    }

    let ENDPOINT_HOST, ENDPOINT_PORT;
    switch (endpointChoice) {
      case '2': ENDPOINT_HOST = '162.159.195.1'; ENDPOINT_PORT = 500; break;
      case '3': ENDPOINT_HOST = 'engage.cloudflareclient.com'; ENDPOINT_PORT = 2408; break;
      default: ENDPOINT_HOST = '162.159.192.1'; ENDPOINT_PORT = 500;
    }

    const dns = DNS_MAP[dnsChoice] || DNS_MAP['1'];
    let dnsList = [...dns.v4];
    if (ipv6) dnsList = dnsList.concat(dns.v6);
    const DNS_LINE = dnsList.join(', ');

    const ALLOWED_IPS = routing === 'lan' ? ALLOWED_LAN : '0.0.0.0/0, ::/0';

    let I1_FINAL = DEFAULT_I1;
    if (customI1 && i1Domain) {
      I1_FINAL = await generateCustomI1(i1Domain);
    }

    const { priv, pub } = generateKeypair();

    const regData = await apiRequest('POST', '/reg', null, {
      install_id: '',
      tos: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      key: pub,
      fcm_token: '',
      type: 'ios',
      locale: 'en_US'
    });

    if (!regData.result || !regData.result.id || !regData.result.token) {
      res.status(500).json({ error: 'Registration failed', details: regData });
      return;
    }

    const id = regData.result.id;
    const token = regData.result.token;

    const patchData = await apiRequest('PATCH', `/reg/${id}`, token, {
      warp_enabled: true
    });

    const peerPub = patchData.result.config.peers[0].public_key;
    const clientIPv4 = patchData.result.config.interface.addresses.v4;
    const clientIPv6 = patchData.result.config.interface.addresses.v6;

    const ADDRESS_LINE = ipv6 ? `${clientIPv4}, ${clientIPv6}` : clientIPv4;
    const KEEPALIVE_LINE = keepaliveOn ? `PersistentKeepalive = ${keepaliveSec}` : '';

    const config = `[Interface]
PrivateKey = ${priv}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = ${I1_FINAL}
Address = ${ADDRESS_LINE}
DNS = ${DNS_LINE}
MTU = ${mtu}

[Peer]
PublicKey = ${peerPub}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${ENDPOINT_HOST}:${ENDPOINT_PORT}
${KEEPALIVE_LINE}`.trim() + '\n';

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="cloudflare-warp.conf"');
    res.status(200).send(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}