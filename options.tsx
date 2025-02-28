import { useEffect, useState } from "react";
import { config } from "./config";
import "./options.css";

const options = () => {
  const [url, setUrl] = useState<string | null>(null);
  const [whoisData, setWhoisData] = useState<any>(null);
  const [googleSafeBrowsingData, setGoogleSafeBrowsingData] = useState<any>(null);
  const [securityScore, setSecurityScore] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    const getCurrentTab = async () => {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tabUrl = tabs[0]?.url;

        if (tabUrl && isValidUrl(tabUrl)) {
          setUrl(tabUrl);
          setLoading(true);

          try {
            const whoisResponse = await fetchWhoisData(tabUrl);
            setWhoisData(whoisResponse);

            const safeBrowsingResponse = await fetchGoogleSafeBrowsing(tabUrl);
            setGoogleSafeBrowsingData(safeBrowsingResponse);

            const analysis = analyzeWhoisData(whoisResponse);
            setSecurityScore(analysis.score);
          } catch (error) {
            console.error("Erreur lors de la récupération des données", error);
          } finally {
            setLoading(false);
          }
        } else {
          console.error("URL invalide : ", tabUrl);
        }
      });
    };

    getCurrentTab();
  }, []);

  const isValidUrl = (url: string) => {
    try {
      new URL(url);
      return true;
    } catch (e) {
      return false;
    }
  };

  const fetchWhoisData = async (url: string) => {
    try {
      const domain = new URL(url).hostname;
      const response = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${config.WHOIS_API_KEY}&domainName=${domain}&outputFormat=json`
      );

      if (!response.ok) {
        throw new Error("Erreur lors de la récupération des données Whois");
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error("Erreur API WhoisXML :", error);
      return null;
    }
  };

  const fetchGoogleSafeBrowsing = async (url: string) => {
    try {
      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.GOOGLE_SAFE_BROWSING_API_KEY}`,
        {
          method: "POST",
          body: JSON.stringify({
            client: {
              clientId: "yourClientID",
              clientVersion: "1.0",
            },
            threatInfo: {
              urlList: [url],
            },
          }),
        }
      );

      if (!response.ok) {
        throw new Error("Erreur lors de la récupération des données Google Safe Browsing");
      }

      const data = await response.json();
      return data;
    } catch (error) {
      console.error("Erreur API Safe Browsing :", error);
      return null;
    }
  };

  const analyzeWhoisData = (whoisData: any) => {
    if (!whoisData || !whoisData.WhoisRecord) {
      return { score: "D", explanation: "Impossible de récupérer les infos Whois du site." };
    }

    const record = whoisData.WhoisRecord;
    const creationDate = record.createdDateNormalized;
    const isAnonymous = record.privacy || false;

    let score = "A";
    let explanation = "Le site semble fiable.";

    if (creationDate) {
      const year = new Date(creationDate).getFullYear();
      const currentYear = new Date().getFullYear();
      const age = currentYear - year;

      if (age < 1) {
        score = "C";
        explanation = "Le domaine est très récent. Prudence recommandée.";
      } else if (age < 5) {
        score = "B";
        explanation = "Le domaine est relativement récent.";
      }
    }

    if (isAnonymous) {
      score = "C";
      explanation += " Le propriétaire du domaine utilise un service d’anonymisation.";
    }

    return { score, explanation };
  };

  const renderScoreExplanation = (score: string) => {
    const explanations = {
      "A": (
        <>
          <h2>Très Sûr</h2>
          <p>
            Le site a une longue histoire avec une réputation bien établie, ce qui
            renforce sa fiabilité. Il est associé à un registrar de confiance et son
            propriétaire n'utilise pas de services d'anonymisation, ce qui facilite la
            vérification de son identité. Cela indique un faible risque de fraude
            ou d'escroquerie.
          </p>
          <p>
            De plus, le site possède une infrastructure sécurisée, offrant une
            protection accrue pour les utilisateurs contre les attaques malveillantes.
            En raison de son ancienneté et de la transparence de ses informations, ce
            site est jugé très sûr.
          </p>
        </>
      ),
      "B": (
        <>
          <h2>Modérément Sûr</h2>
          <p>
            Le domaine est relativement récent, mais il est enregistré auprès d'un
            registrar de confiance. Bien que le site ne présente pas de risques majeurs,
            sa jeunesse peut parfois poser des préoccupations. Il est important de
            rester vigilant, surtout s'il présente des caractéristiques suspectes ou
            manque de transparence.
          </p>
          <p>
            Les propriétaires du site sont visibles, ce qui est un bon signe. Cependant,
            un site modérément sûr peut encore être susceptible à certaines vulnérabilités,
            notamment si ses informations de sécurité ne sont pas à jour.
          </p>
        </>
      ),
      "C": (
        <>
          <h2>Moins Sûr</h2>
          <p>
            Le site est relativement nouveau et utilise un service d'anonymisation pour
            masquer l'identité de son propriétaire, ce qui peut compliquer la vérification
            de sa crédibilité. Bien que ce ne soit pas nécessairement un signe de fraude,
            cela indique un niveau de risque plus élevé.
          </p>
          <p>
            Les sites utilisant de tels services sont souvent associés à des activités
            suspectes, comme des escroqueries en ligne ou des tentatives de phishing. Il
            est donc conseillé de faire preuve de prudence lors de l'interaction avec ces
            sites.
          </p>
        </>
      ),
      "D": (
        <>
          <h2>Très Risqué</h2>
          <p>
            Ce site présente plusieurs indicateurs de risques, notamment sa jeunesse et
            le fait qu'il utilise des services d'anonymisation. Il est associé à un domaine
            récent, ce qui suggère qu'il n'a pas encore eu le temps de bâtir une réputation
            solide.
          </p>
          <p>
            Les sites classés très risqués ont souvent été créés dans le but de mener des
            attaques malveillantes ou de voler des informations personnelles. Il est fortement
            recommandé d'éviter d'interagir avec de tels sites.
          </p>
        </>
      ),
    };

    return explanations[score] || <p>Impossible de déterminer la sécurité du site.</p>;
  };

  return (
    <div className="detailed-info-container">
      <h1><strong>{url ? new URL(url).hostname : "URL invalide"}</strong></h1>
      {loading && <p>Chargement...</p>}

      {url && (
        <>
          {securityScore && (
            <div className="security-score-container">
              
              <div className="score-explanation">
                {renderScoreExplanation(securityScore)}
              </div>
            </div>
          )}

          {whoisData && whoisData.WhoisRecord && (
            <div className="whois-info">
              <h2>🔍 Informations Whois</h2>
              <p><strong>🗓️ Créé le :</strong> {whoisData.WhoisRecord.createdDateNormalized || "Inconnu"}</p>
              <p><strong>🏢 Registrar :</strong> {whoisData.WhoisRecord.registrarName || "Inconnu"}</p>
              <p><strong>🕵️ Anonymisation :</strong> {whoisData.WhoisRecord.privacy ? "Oui 🔴" : "Non 🟢"}</p>
            </div>
          )}

          {googleSafeBrowsingData && (
            <div className="safe-browsing-info">
              <h2>🛡️ Sécurité Google Safe Browsing</h2>
              <p>{googleSafeBrowsingData.matches ? "Le site est classé comme dangereux 🚨" : "Le site semble sûr ✅"}</p>
            </div>
          )}

          <div className="separator"></div>

          <a href={`popup.html?url=${encodeURIComponent(url)}`} className="back-to-popup">
            Retour
          </a>
        </>
      )}
    </div>
  );
};

export default options;
