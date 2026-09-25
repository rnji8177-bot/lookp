function formatData(obj, indent = "") {
  let output = "";
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      output += `${indent}🔹 ${key.toUpperCase()}:\n`;
      if (value.length === 0) {
        output += `${indent}   (empty)\n`;
      } else {
        value.forEach((item, index) => {
          output += `${indent}   ▶ RECORD ${index + 1}:\n`;
          output += formatData(item, indent + "      ");
        });
      }
    } else if (typeof value === "object" && value !== null) {
      output += `${indent}🔹 ${key.toUpperCase()}:\n`;
      output += formatData(value, indent + "   ");
    } else {
      output += `${indent}🔹 ${key.toUpperCase()}: ${value}\n`;
    }
  }
  return output;
}

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
      resultDiv.innerHTML = formatData(data);
    }
  } catch (err) {
    resultDiv.innerHTML = `⚠️ Error: ${err.message}`;
  }
}
