import fetch from "node-fetch";

async function callRawSign(walletId, authSignature, hash) {
  const url = `https://api.privy.io/v1/wallets/${walletId}/raw_sign`;

  const options = {
    method: "POST",
    headers: {
      Authorization:
        "Basic Y21kaXA0ZW1sMDA2NGw0MGpzcHluOWlpaTo1aDhBS3dtek1LcVJaTXdpc0VvUDJ2dGhIUjVTRGlvb25YZ01yWW9CU21Tb2h3cjNnRHB5d2tpUUVnWTZIc2VHUEZtR0RzYXFveVZKRWY3eVphdWV1NzRF",
      "privy-app-id": "cmdip4eml0064l40jspyn9iii",
      "privy-authorization-signature": authSignature, // 🔑 your generated signature here
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      params: {
        hash, // 🔑 hash of your tx you want signed
      },
    }),
  };

  try {
    const response = await fetch(url, options);
    const data = await response.json();
    console.log("Raw sign response:", data);
    return data;
  } catch (error) {
    console.error("Error calling raw_sign:", error);
    throw error;
  }
}

// Example usage
(async () => {
  const walletId = "fcvsl05oo5muzkdizixbvz62";
  const authSignature = "<PUT-YOUR-SIGNATURE-HERE>";
  const hash = "<TX-HASH-HERE>";

  await callRawSign(walletId, authSignature, hash);
})();
