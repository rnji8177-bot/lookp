async function lookupNumber() {
  const number = document.getElementById("numberInput").value;
  const resultDiv = document.getElementById("result");
  
  resultDiv.innerHTML = "⏳ Fetching data...";

  try {
    const response = await fetch(`/lookup?number=${number}`);
    
    if (!response.ok) {
      throw new Error("Proxy not responding");
    }

    const data = await response.json();

    if (data.error || Object.keys(data).length === 0) {
      resultDiv.innerHTML = "❌ No data found!";
    } else {
      let output = "";
      // Loop through all keys in the JSON
      for (const [key, value] of Object.entries(data)) {
        output += `🔹 ${key.toUpperCase()}: ${value}\n`;
      }
      resultDiv.innerHTML = output;
    }
  } catch (err) {
    resultDiv.innerHTML = `⚠️ Error: ${err.message}`;
  }
}
