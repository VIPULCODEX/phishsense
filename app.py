import html
import re

import streamlit as st

from inference import analyze_text, load_model

st.set_page_config(page_title="Phish Sense", layout="centered")

st.title("Phish Sense")
st.caption("Context-Aware Scam Detection System (Hybrid ML + Rules)")


@st.cache_resource
def get_model():
    return load_model()


def render_highlighted_text(text: str, words):
    if not text:
        return ""
    if not words:
        return html.escape(text)

    rendered = html.escape(text)
    unique_words = sorted(set(words), key=len, reverse=True)

    for word in unique_words:
        if not word:
            continue
        escaped_word = re.escape(html.escape(word))
        pattern = re.compile(rf"(?i)\b({escaped_word})\b")
        rendered = pattern.sub(
            r"<mark style='background-color:#ffe082;padding:0.1rem 0.25rem;border-radius:0.25rem;'>\1</mark>",
            rendered,
        )
    return rendered


input_text = st.text_area(
    "Enter message text",
    height=150,
    placeholder="Example: Urgent! Verify your account now at http://bit.ly/xyz123",
)

if st.button("Analyze", type="primary", use_container_width=True):
    if not input_text.strip():
        st.warning("Please enter text to analyze.")
    else:
        model = get_model()
        result = analyze_text(input_text, model=model)

        prediction = result["prediction"]
        risk_score = result["risk_score"]

        if prediction == "safe":
            st.success(f"Prediction: {prediction}")
        else:
            st.error(f"Prediction: {prediction}")

        st.write(f"Risk Score: **{risk_score}%**")
        st.progress(risk_score / 100)

        st.subheader("Highlighted Suspicious Words")
        highlighted_html = render_highlighted_text(input_text, result["highlighted_words"])
        st.markdown(
            f"<div style='line-height:1.8;font-size:1rem'>{highlighted_html}</div>",
            unsafe_allow_html=True,
        )

        st.subheader("Explanation")
        for reason in result["reasons"]:
            st.markdown(f"- {reason}")

        st.subheader("URL Check")
        if result["url_flag"] == "Suspicious":
            st.error("URL flag: Suspicious")
        else:
            st.success("URL flag: Safe")

        st.subheader("JSON Output")
        st.json(result)
