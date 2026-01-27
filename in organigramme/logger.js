const { spawn } = require('child_process');
const path = require('path');

function logger(req, res, next) {
  const start = Date.now();

  res.on("finish", () => {
    const ip =
      (req.headers["x-forwarded-for"] &&
        req.headers["x-forwarded-for"].split(",")[0]) ||
      req.socket.remoteAddress ||
      "unknown";

    const duration = Date.now() - start;
    const timestamp = new Date().toISOString();

    let bodyString = "";
    if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
      try {
        bodyString = " body:" + JSON.stringify(req.body);
      } catch {
        bodyString = " body:[unreadable]";
      }
    }

    const ua = req.headers["user-agent"] || "unknown-UA";
    const logLine = `${timestamp} - ${ip} - ${req.method} ${req.originalUrl}${bodyString} - ${res.statusCode} - ${duration}ms ua:${ua}\n`;

    // Lancer votre script Python
    const pythonProcess = spawn('python', ['chiffrer.py'], { 
      cwd: __dirname 
    });

    // Envoyer les logs via stdin
    pythonProcess.stdin.write(logLine);
    pythonProcess.stdin.end();

    pythonProcess.on('error', (error) => {
      console.error("Erreur lors du chiffrement des logs:", error);
    });
  });

  next();
}

module.exports = { logger };