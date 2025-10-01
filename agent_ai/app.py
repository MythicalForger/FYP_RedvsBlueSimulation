from flask import Flask, request, jsonify
import os

app = Flask(__name__)

LOG_FILE = "/app/logs/ai.log"
OUTPUT_FILE = "/app/outputs/note.txt"

@app.route("/prompt", methods=["POST"])
def prompt():
    data = request.json
    text = data.get("text", "")
    response = ""

    if text.startswith("search:"):
        query = text.split("search:",1)[1].strip()
        response = f"Dummy search result for '{query}'"   # later hook to duckduckgo
    elif text.startswith("write:"):
        content = text.split("write:",1)[1].strip()
        with open(OUTPUT_FILE, "a") as f:
            f.write(content + "\n")
        response = f"Written to note.txt: {content}"
    else:
        response = "Unrecognized command."

    with open(LOG_FILE, "a") as log:
        log.write(f"PROMPT: {text} -> RESPONSE: {response}\n")

    return jsonify({"response": response})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

