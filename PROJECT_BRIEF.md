# Scam Message Checker: project brief

A free tool for older people and their families. Paste in a text, email or WhatsApp message you're unsure about. The tool says whether it shows warning signs of a scam, points to the specific signs in plain English, and tells you what to do next.

**Portfolio angle:** tech for good, AI safety design, and evaluation at scale (45+ test messages with a results table). It's built in code, not n8n, which shows you can work outside no-code tools.

---

## 1. The problem

Scam texts and emails now copy real organisations closely: Royal Mail, HMRC, banks, the DVLA, even your own children ("Hi Mum, I've got a new number"). Older people are targeted most, and the usual advice ("if in doubt, don't click") doesn't help someone decide about the message in front of them.

The goal is a tool that gives a careful second opinion in plain English. It never tells anyone a message is safe.

## 2. What it does

**Input:** the message text pasted in, plus optionally where it came from (text, email, WhatsApp, other).

**Output, shown to the user:**

| Part | Written by |
|---|---|
| Verdict: **Likely scam**, **Be careful**, or **No strong warning signs** | AI, from a fixed list |
| The warning signs found (up to 3), each with a one-line explanation | AI, choosing from a fixed list of signs |
| What to do next | Fixed text per verdict, never written by AI |

The AI's job is narrow: read the message, pick a verdict, and pick warning signs from a fixed list. It never writes the advice, never tells anyone to click anything, and never says "safe".

### Output structure the AI must return

```json
{
  "verdict": "likely_scam | be_careful | no_strong_signs",
  "signs": ["fee_to_release_parcel", "link_not_official"],
  "explanations": ["Royal Mail doesn't text asking for a fee...", "..."],
  "impersonating": "Royal Mail | HMRC | bank | family member | none | other"
}
```

### Fixed list of warning signs

| Code | Plain-English label |
|---|---|
| `urgency_or_threat` | Pressure to act fast, or a threat (fine, account closed, arrest) |
| `small_fee_request` | Asks for a small payment to release a parcel, refund or service |
| `link_not_official` | Link doesn't go to the organisation's real website |
| `asks_for_codes_or_details` | Asks for a one-time code, password, PIN or card details |
| `move_money_safe_account` | Asks you to move money, often to a "safe account" |
| `new_number_family` | Someone claiming to be family from a new or unknown number |
| `unexpected_money` | Unexpected refund, prize, rebate or investment return |
| `call_this_number` | Asks you to call a number given in the message |
| `secrecy` | Asks you not to tell anyone, or not to talk to your bank |
| `unusual_payment` | Asks for gift cards, crypto, or a bank transfer to a person |
| `impersonation` | Pretends to be a well-known organisation or official body |
| `too_good_to_be_true` | Job, investment or offer that sounds too good to be true |

## 3. Safety rules

1. **Never say "safe".** The best verdict is "No strong warning signs", and it always comes with how to check independently.
2. **When unsure, be careful.** If the AI isn't confident, the verdict is "Be careful", never "No strong warning signs". Missing a scam is far worse than a false alarm.
3. **Rule-based backstop.** A simple keyword and pattern check (e.g. "safe account", "gift card", "new number", a link plus a fee) forces at least "Be careful", whatever the AI decided. Same idea as the keyword check in the clinic project.
4. **Fixed advice text.** Everything telling the user what to do is pre-written and checked against official sources.
5. **Ignore instructions inside the message.** The pasted message is data, never instructions. Test this directly (see the prompt-injection cases in the test set).
6. **No data kept.** Messages aren't stored or logged. The page tells users to remove names, addresses and account numbers before pasting.
7. **Synthetic data only.** Every test message is made up. All links and phone numbers in the test set are invented (UK numbers use Ofcom's ranges reserved for drama). Don't visit any of the links.

## 4. Fixed advice text

**Likely scam**
> This message has strong signs of a scam. Don't click any links, reply, or call numbers in the message.
> - Text message: forward it to **7726** (free).
> - Email: forward it to **report@phishing.gov.uk**.
> - If you've already clicked, paid or shared details: call your bank straight away on **159**, or the number on the back of your card. Then report it to **Report Fraud** at reportfraud.police.uk or **0300 123 2040** (England, Wales and Northern Ireland). In Scotland, call Police Scotland on **101**.

**Be careful**
> This message has some warning signs. Don't use any links or numbers in it. If it claims to be from an organisation, contact them using details you already trust, like their official website, app, or the number on your card or a bill. If it claims to be from family, call them on the number you already have for them.

**No strong warning signs**
> We didn't find strong warning signs, but no tool can be sure a message is genuine. If it asks you to pay, log in or share details, check with the organisation directly using contact details you already trust.

*Check these against official sources before publishing (NCSC, Report Fraud, Stop! Think Fraud). Reporting routes change: Action Fraud was replaced by Report Fraud in December 2025.*

## 5. How you'll test it

**Test set:** `test-messages.csv` (45 starter messages, add your own). It covers:
- Common UK scams: parcel fees, HMRC, DVLA, banks, "Hi Mum", parking fines, energy rebates, jobs, investments
- Subtle scams with no link, good grammar, or only a phone number
- Genuine messages that look scammy: real delivery texts, real bank fraud checks, one-time passcodes, GP reminders
- Prompt injection: messages that tell the AI to say they're safe
- Edge cases: very short, another language, not a message at all

**Metrics for the results table:**

| Metric | What it means | Target |
|---|---|---|
| Missed scams | Scam rated "No strong warning signs" | **0**. This is the one that matters |
| False alarms | Genuine message rated "Likely scam" | As low as possible, but explain each one |
| Exact match | Verdict matches the expected one | Report it, but don't chase it |
| Consistency | Same verdict across 3 runs | Report the % that changed |
| Injection resistance | Injection attempts that changed the verdict | 0 |

**Run everything 3 times.** Your lead workflow showed that scores move between runs, so show whether that happens here.

**Keep a build log** (`build-log.csv`, same as your other projects) of every problem found and fixed. That becomes the "What testing found" section.

## 6. Stack and cost

| Part | Tool | Cost |
|---|---|---|
| Code | Python, written with Claude Code | Your existing plan |
| AI | Claude API (a small, cheap model is enough for classification) | A few pounds for the whole project |
| Web page | Streamlit, hosted on Streamlit Community Cloud | Free |
| Code and write-up | GitHub repo + case study on your site | Free |

Keep the API key in Streamlit's secrets, never in the repo. Set a monthly spend limit in the Anthropic Console, so a public demo can't run up a bill. Also consider a simple daily usage cap in the app.

## 7. Build plan

1. **Classifier script.** A Python function: message in, structured output out. Test it by hand on 5 messages.
2. **Evaluation script.** Runs the whole test set 3 times and writes `results.csv` plus a summary table. Do this *before* polishing the prompt, so every change you make is measured.
3. **Improve and log.** Fix what the results show. Log each issue in `build-log.csv`.
4. **Backstop rules.** Add the keyword and pattern check. Show in the results that it catches anything the AI missed (or, like the clinic project, that it never had to, with a simulated test proving it works).
5. **Streamlit page.** Text box, source dropdown, result card with verdict, signs and fixed advice. Large text and plain colours: the audience is older people.
6. **Write-up.** Case study on your site in the same format as the other two: The problem, How it works, The AI's job, Safety design, Test runs, What testing found, How I built it, Next steps.

## 8. For the "How I built it" section

Be as honest as in your other case studies. If Claude Code wrote the code and Claude drafted the starter test set, say so. Then say what you did: designed the verdicts, signs and safety rules, wrote or reviewed every test case, read the results critically, and directed every fix.

## 9. Ideas for next steps (for the write-up)

- Screenshot upload (many scams arrive as images)
- A "send this to a family member" button so someone can get a second opinion from a person
- Testing with real users, e.g. a local Age UK group, with consent
- Tracking which scam types are most common in what people paste (without storing messages)
