
import json
import urllib.request
import urllib.error
import socket

from django.shortcuts import render
from django.contrib.auth.decorators import login_required


OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2:1b"


@login_required
def assistant_home(request):

    answer = None
    error = None
    question = ""

    if request.method == "POST":

        question = request.POST.get("question", "").strip()

        if not question:
            error = "Please enter a cybersecurity question."

        elif len(question) > 1000:
            error = "Your question must not exceed 1000 characters."

        else:

            payload = {
                "model": MODEL_NAME,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 600
                },
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are an AI Cyber Awareness Assistant. "
                            "Give accurate, beginner-friendly and practical "
                            "cybersecurity education.\n\n"

                            "RESPONSE RULES:\n"
                            "1. Answer the user's question directly.\n"
                            "2. Use short paragraphs and numbered steps "
                            "when explaining procedures.\n"
                            "3. Keep answers concise but complete.\n"
                            "4. Finish every sentence and every list item.\n"
                            "5. Never stop halfway through a sentence or list.\n"
                            "6. Use normal Markdown formatting. Do not put "
                            "backslashes before Markdown symbols.\n"
                            "7. Do not add unrelated advice or unnecessary "
                            "'What not to do' sections.\n\n"

                            "CYBERSECURITY SAFETY:\n"
                            "For suspicious links, advise users not to click, "
                            "not to download attachments, and to verify the "
                            "sender through a separate trusted channel. "
                            "Never tell users to report suspicious messages "
                            "by replying to the suspicious sender.\n"
                            "If a user has already clicked a suspicious link, "
                            "explain how to close the page, avoid entering "
                            "information, and seek help from a trusted "
                            "adult or IT support if account details were "
                            "shared. Recommend changing affected passwords "
                            "through the official website and reviewing "
                            "account security.\n"
                            "Explain that clearing browser cache does not "
                            "by itself secure an account.\n"
                            "Never advise users to share passwords, OTPs, "
                            "recovery codes or banking credentials.\n\n"

                            "Focus on phishing prevention, online safety, "
                            "password security, malware awareness, QR code "
                            "safety and secure browsing. Do not provide "
                            "instructions for hacking accounts, stealing "
                            "credentials, deploying malware or bypassing "
                            "security.\n"
                            "If a question is unrelated to cybersecurity, "
                            "politely guide the user back to cybersecurity."
                        )
                    },
                    {
                        "role": "user",
                        "content": question
                    }
                ]
            }

            try:

                data = json.dumps(payload).encode("utf-8")

                req = urllib.request.Request(
                    OLLAMA_URL,
                    data=data,
                    headers={
                        "Content-Type": "application/json"
                    },
                    method="POST"
                )

                with urllib.request.urlopen(
                    req,
                    timeout=90
                ) as response:

                    result = json.loads(
                        response.read().decode("utf-8")
                    )

                answer = result.get(
                    "message", {}
                ).get(
                    "content", ""
                ).strip()

                # Correct escaped Markdown symbols from model output.
                answer = answer.replace(r"\*\*", "**")
                answer = answer.replace(r"\*", "*")

                if not answer:
                    error = (
                        "The AI did not return a response. "
                        "Please try again."
                    )

            except (socket.timeout, TimeoutError):
                error = (
                    "The AI response took too long. "
                    "Please try again."
                )

            except urllib.error.URLError:
                error = (
                    "Unable to connect to Ollama. "
                    "Please make sure Ollama is running."
                )

            except (ValueError, KeyError, json.JSONDecodeError):
                error = (
                    "Unable to process the AI response. "
                    "Please try again."
                )

            except Exception:
                error = (
                    "Something went wrong while generating "
                    "the answer."
                )

    return render(
        request,
        "cyber_assistant/assistant.html",
        {
            "question": question,
            "answer": answer,
            "error": error
        }
    )
