
import { useEffect, useState } from "react";
import { config } from "./config";
import "./popup.css";

const Popup = () => {
  const [securityScore, setSecurityScore] = useState<string | null>(null);
  const [scoreExplanation, setScoreExplanation] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [url, setUrl] = useState<string | null>(null);

  useEffect(() => {
    const getCurrentTab = async () => {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tabUrl = tabs[0]?.url;

        if (tabUrl) {
          setUrl(tabUrl);
          setLoading(true);

          try {
            const [whoisResponse, safeBrowsingResponse] = await Promise.all([
              fetchWhoisData(tabUrl),
              fetchSafeBrowsingData(tabUrl)
            ]);

            const analysis = analyzeData(whoisResponse, safeBrowsingResponse);

            setSecurityScore(analysis.score);
            setScoreExplanation(analysis.explanation);
          } catch (error) {
            console.error("Erreur lors de l'analyse :", error);
            setScoreExplanation("⚠️ Impossible d'analyser.");
            setSecurityScore("C");
          } finally {
            setLoading(false);
          }
        }
      });
    };

    getCurrentTab();
  }, []);

  const fetchWhoisData = async (url: string) => {
    const domain = new URL(url).hostname;
    const response = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${config.WHOIS_API_KEY}&domainName=${domain}&outputFormat=json`
    );
    return response.json();
  };

  const fetchSafeBrowsingData = async (url: string) => {
    const requestBody = {
      client: { clientId: "safyscore-extension", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.GOOGLE_SAFE_BROWSING_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody)
      }
    );
    return response.json();
  };

  const analyzeData = (whoisData: any, safeBrowsingData: any) => {
    let score = "A";
    let explanation = "✅ Sécurisé.";

    if (safeBrowsingData && safeBrowsingData.matches) {
      score = "D";
      explanation = "🚨 Dangereux (Google).";
    }

    if (whoisData && whoisData.WhoisRecord) {
      const record = whoisData.WhoisRecord;
      const creationDate = record.createdDateNormalized;
      const isAnonymous = record.privacy || false;

      if (creationDate) {
        const year = new Date(creationDate).getFullYear();
        const currentYear = new Date().getFullYear();
        const age = currentYear - year;

        if (age < 1) {
          score = score === "D" ? "D" : "C";
          explanation += " 🔶 Site récent.";
        } else if (age < 5) {
          score = score === "D" ? "D" : "B";
          explanation += " 🟠 Site relativement récent.";
        }
      }

      if (isAnonymous) {
        score = score === "D" ? "D" : "C";
        explanation += " ⚠️ Propriétaire anonyme.";
      }
    } else {
      score = "C";
      explanation = "❓ Informations Whois manquantes.";
    }

    return { score, explanation };
  };

  const getScoreDetails = (score: string | null) => {
    switch (score) {
        case "A":
  return [
    { icon: "✅", text: "Domaine fiable" },
    { icon: "🔒", text: "Protection renforcée" },
    { icon: "🌟", text: "Réputation établie" }
  ];

  case "B":
    return [
      { icon: "⚖️", text: "Risques faibles" },
      { icon: "🔍", text: "Examen recommandé" },
      { icon: "📅", text: "Site relativement récent" }
    ];
    
  
    case "C":
      return [
        { icon: "⚠️", text: "Attention requise" },
        { icon: "🔓", text: "Sécurité limitée" },
        { icon: "🕵️‍♂️", text: "Propriétaire anonyme" }
      ];
    
      case "D":
  return [
    { icon: "🚫", text: "Site dangereux" },
    { icon: "⚠️", text: "Risque élevé" },
    { icon: "❌", text: "Éviter d'interagir" }
  ];

      default:
        return [];
    }
  };

  return (
    <div>
      <div className="popup-container">
        {loading && (
          <div className="loading-container">
            <p className="loading">Chargement...</p>
          </div>
        )}

        {securityScore && (
          <div className="score-container">
            <div className={`score-circle score-${securityScore}`}>
              {securityScore}
            </div>
            <div className="score-details">
              {getScoreDetails(securityScore).map((item, index) => (
                <div key={index} className="feature">
                  {item.icon} <span>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {url && (
  <div className="more-info">
    <a href={`options.html?url=${encodeURIComponent(url)}`} className="arrow-button">
      <span className="arrow">➡️</span>
    </a>
  </div>
)}

    </div>
  );
};

export default Popup;
