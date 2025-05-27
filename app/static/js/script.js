async function checkURL() {
    const url = document.getElementById('urlInput').value.trim();
    const resultDiv = document.getElementById('result');

    if (!url) {
        resultDiv.innerText = "Por favor, insira uma URL.";
        return;
    }

    resultDiv.innerText = "Analisando...";

    try {
        const response = await fetch('/check', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (data.error) {
            resultDiv.innerText = `Erro: ${data.error}`;
            return;
        }

        const whois = data.whois || {};
        const vt = data.virustotal || {};

        resultDiv.innerText = `
🔗 URL: ${data.url}
🕒 Análise feita em: ${data.timestamp}

🌐 Protocolo HTTPS: ${data.https ? "✔️ Sim" : "❌ Não"}

📑 Informações WHOIS:
- Domínio: ${whois.domain_name || "N/A"}
- Criado em: ${whois.creation_date || "N/A"}
- Expira em: ${whois.expiration_date || "N/A"}
- Registrar: ${whois.registrar || "N/A"}
- Name Servers: ${Array.isArray(whois.name_servers) ? whois.name_servers.join(", ") : whois.name_servers || "N/A"}
- Emails: ${Array.isArray(whois.emails) ? whois.emails.join(", ") : whois.emails || "N/A"}

🛡️ VirusTotal:
- Maliciosos: ${vt.malicious !== undefined ? vt.malicious : "N/A"}
- Suspeitos: ${vt.suspicious !== undefined ? vt.suspicious : "N/A"}
- Seguros: ${vt.harmless !== undefined ? vt.harmless : "N/A"}
- Total de análises: ${vt.total !== undefined ? vt.total : "N/A"}

${vt.error ? "\n⚠️ Aviso VirusTotal: " + vt.error : ""}
        `;

    } catch (error) {
        resultDiv.innerText = `Erro na requisição: ${error}`;
    }
}

let bright = document.getElementById('bright')
let body =  document.querySelector('body')

bright.addEventListener('click', ()=>{
    bright.classList.toggle('dark')
    body.classList.toggle('dark')
})