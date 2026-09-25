function formatData(obj, indent = "") {
  let output = "";
  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      output += `${indent}▶ RECORD ${index + 1}:\n`;
      output += formatData(item, indent + "   ");
    });
  } else if (typeof obj === "object" && obj !== null) {
    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === "object" && value !== null) {
        output += `${indent}🔹 ${key.toUpperCase()}:\n`;
        output += formatData(value, indent + "   ");
      } else {
        output += `${indent}🔹 ${key.toUpperCase()}: ${value}\n`;
      }
    }
  } else {
    output += `${indent}${obj}\n`;
  }
  return output;
}

async function lookupNumber() {
  const number = document.getElementById("numberInput").value;
  const resultDiv = document.getElementById("result");
  
  resultDiv.innerHTML = "⏳ Fetching data...";

  try {
    const response = await fetch(`/lookup?number=${number}`);
    if (!response.ok) throw new Error("Proxy not responding");

    const data = await response.json();

    if (!data || Object.keys(data).length === 0) {
      resultDiv.innerHTML = "❌ No data found!";
    } else {
      resultDiv.innerHTML = formatData(data);
    }
  } catch (err) {
    resultDiv.innerHTML = `⚠️ Error: ${err.message}`;
  }
}
