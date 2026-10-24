import { AnalysisResult, ScamVerdict, RiskLevel } from '../types.ts';

// Common typo & abbreviation mapping for Indian digital payment scams
const FUZZY_PATTERNS = {
  account: /\b(acount|acnt|acc|a\/c|a\\c|acunt|khata|khate|acconts?)\b/i,
  customer: /\b(coustomer|costumer|custmr|custmer|castomar|grahak|customr)\b/i,
  blocked: /\b(bloacked|blckd|blokd|deactivat(ed)?|suspend(ed)?|freeze?d?|band|rok)\b/i,
  immediately: /\b(immedetly|immediatly|imediatly|urgnt|urgently|turant|jaldi|foran|today|aaj)\b/i,
  verify: /\b(verfy|varify|varification|verifaction|satypan|updat(e|ed))\b/i,
  lottery: /\b(lotry|lotery|inam|jeeta|prize|kbc|lucky\s*draw|reward|vouchar)\b/i,
  cashback: /\b(cshbck|cashbk|reward|cash\s*reward|scratch\s*card|claim\s*refund)\b/i,
  power_cut: /\b(bijli|electricity|power\s*cut|power\s*supply|disconnect(ed)?|light\s*kat)\b/i,
  qr_code: /\b(qr|qr\s*code|scan|scanner|bar\s*code|scan\s*karo)\b/i,
  receive_money: /\b(receive|receve|accept|credit|paisa\s*aayega|paisa\s*lo|get\s*money|claim)\b/i,
  upi_pin: /\b(upi\s*pin|pin|mpin|atm\s*pin|passcode|secret\s*pin|pin\s*dalo|enter\s*pin)\b/i,
  otp: /\b(otp|one\s*time\s*password|verification\s*code|6\s*digit\s*code|sms\s*code)\b/i,
  remote_app: /\b(anydesk|teamviewer|rustdesk|quicksupport|screen\s*share|apk|\.apk)\b/i,
  job_task: /\b(work\s*from\s*home|wfh|part[\s-]*time|like\s*youtube|rating\s*google|telegram\s*task|daily\s*earn)\b/i,
  bank_name: /\b(sbi|yono|hdfc|icici|axis|pnb|bob|canara|kotak|paytm|phonepe|gpay|google\s*pay)\b/i,
  army_officer: /\b(army|defence|military|officer|posted|cantt|transfer|cantonment)\b/i,
};

// Suspicious URL indicators
const SUSPICIOUS_TLDS = /\.(apk|xyz|top|site|vip|icu|click|in\.net|cc|work|buzz|rest|live|club|stream|fun)(\/|$|\?)/i;
const SHORTENED_LINKS = /\b(bit\.ly|tinyurl\.com|is\.gd|t\.co|cutt\.ly|rb\.gy|shorturl\.at|gg\.gg)\b/i;
const IP_ADDRESS_URL = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
const UNTRUSTED_SCHEME = /http:\/\//i;
const OFFICIAL_BANK_DLT_HEADERS = /\b(AX-|VM-|VK-|JM-|AD-|BZ-|DZ-|JD-|VK-)[A-Z]{5,6}\b/i;
const PHONE_NUMBER_PATTERN = /(\+?91[\s-]?)?[6-9]\d{9}\b/;

export function analyzeMessageInstant(
  rawMessage: string,
  channel: string = 'SMS'
): AnalysisResult {
  const text = rawMessage.trim();
  const lower = text.toLowerCase();

  // Red flags detected
  const warningSigns: string[] = [];
  const recommendedActions: string[] = [];
  let goldenRuleViolation: string | undefined = undefined;
  let cybercrimeReportingNeeded = false;

  // 1. Check for prompt injection attempt inside untrusted text
  const isPromptInjection =
    /ignore\s+(all\s+)?(previous\s+)?instructions/i.test(text) ||
    /system\s*override/i.test(text) ||
    /say\s+this\s+is\s+(safe|legitimate)/i.test(text) ||
    /pretend\s+you\s+are/i.test(text);

  if (isPromptInjection) {
    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Malicious Prompt Injection & Manipulation Attempt',
      summary:
        'The input contains deceptive instructions attempting to bypass security evaluations. This is a common tactic used by cybercriminals.',
      explanation:
        'The provided text attempts to force the security analyzer into declaring malicious content safe. Genuine financial notices never include commands to ignore safety rules or override security software.',
      warningSigns: [
        'Detected prompt injection command designed to disable scam detectors',
        'Deceptive phrasing concealing underlying malicious intent',
      ],
      recommendedActions: [
        'Do not engage with the sender',
        'Block and report the contact immediately',
        'Never click on any associated links or download files',
      ],
      confidenceScore: 99,
      cybercrimeReportingNeeded: true,
    };
  }

  // 2. Check for Links & APK files
  const hasApk = /\.apk\b/i.test(text);
  const hasSuspiciousTld = SUSPICIOUS_TLDS.test(text);
  const hasShortLink = SHORTENED_LINKS.test(text);
  const hasIpUrl = IP_ADDRESS_URL.test(text);
  const hasHttpOnly = UNTRUSTED_SCHEME.test(text) && !/https:\/\//i.test(text);
  const hasAnyLink = /https?:\/\/|www\./i.test(text) || hasShortLink || hasSuspiciousTld;

  if (hasApk) {
    warningSigns.push('Contains a direct Android APK (.apk) installer link. Banks NEVER distribute apps via SMS or WhatsApp links.');
  }
  if (hasSuspiciousTld) {
    warningSigns.push('Points to an unverified or high-risk domain extension commonly used for disposable phishing sites.');
  }
  if (hasShortLink) {
    warningSigns.push('Uses a shortened URL (e.g. bit.ly, tinyurl) to obscure the true malicious destination.');
  }
  if (hasIpUrl) {
    warningSigns.push('Uses a raw IP address instead of an authenticated domain name.');
  }
  if (hasHttpOnly && hasAnyLink) {
    warningSigns.push('Uses unencrypted "http://" protocol instead of secure HTTPS.');
  }

  // 3. Typo and grammatical degradation detection
  const hasTypoAccount = FUZZY_PATTERNS.account.test(text);
  const hasTypoCustomer = FUZZY_PATTERNS.customer.test(text);
  const hasTypoBlocked = FUZZY_PATTERNS.blocked.test(text);
  const hasTypoImmediately = FUZZY_PATTERNS.immediately.test(text);
  const hasTypoVerify = FUZZY_PATTERNS.verify.test(text);
  const hasUrgency =
    hasTypoImmediately ||
    /\b(24\s*hours?|tonight|9:30\s*pm|immediately|penalty|legal\s*action|police|fir|warrant)\b/i.test(text);

  const typoCount = [
    /\b(coustomer|costumer|custmr)\b/i.test(text),
    /\b(acount|a\/c|blckd|bloacked)\b/i.test(text),
    /\b(immedetly|immediatly|urgnt)\b/i.test(text),
    /\b(verfy|varify)\b/i.test(text),
    /\bpancard\b/i.test(text),
    /\bur\b/i.test(text) && (hasTypoAccount || hasTypoBlocked),
  ].filter(Boolean).length;

  if (typoCount >= 2) {
    warningSigns.push('Contains noticeable spelling errors and informal slang ("coustomer", "acount", "ur", "verfy") uncharacteristic of official corporate communications.');
  }

  // 4. Detect Specific Scam Archetypes

  // Archetype A: The Classic UPI QR Code "Receive Money" Inversion (OLX / Buyer Fraud)
  const mentionsQr = FUZZY_PATTERNS.qr_code.test(text);
  const mentionsReceive = FUZZY_PATTERNS.receive_money.test(text) || /\b(credit|transfer|sent|advance|approved)\b/i.test(text);
  const mentionsPin = FUZZY_PATTERNS.upi_pin.test(text);
  const mentionsArmy = FUZZY_PATTERNS.army_officer.test(text) || /\bolx\b/i.test(text);

  if (mentionsQr && (mentionsReceive || mentionsPin || mentionsArmy)) {
    goldenRuleViolation =
      'UPI PIN is ONLY required to SEND money. Scanning a QR code ALWAYS debits funds from your bank account, it NEVER credits money.';
    warningSigns.push('Claims that you need to scan a QR code or enter your UPI PIN to receive money or accept payment.');
    if (mentionsArmy) {
      warningSigns.push('Impersonates defense or army personnel to gain quick trust and avoid in-person verification.');
    }
    if (mentionsPin) {
      warningSigns.push('Asks for a 4-digit or 6-digit UPI PIN to be typed, which will instantly authorize an outgoing debit.');
    }

    recommendedActions.push('Do NOT scan the QR code under any circumstances.');
    recommendedActions.push('Never enter your UPI PIN on Google Pay, PhonePe, Paytm, or any banking app for incoming funds.');
    recommendedActions.push('Block and report the sender on WhatsApp, OLX, or the platform where they contacted you.');
    recommendedActions.push('If you already entered your PIN, immediately call 1930 and report to your bank to freeze UPI.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'UPI QR Code Payment Inversion Scam',
      summary:
        'This is a dangerous payment inversion fraud. Entering your UPI PIN or scanning the QR code will drain money from your account instead of crediting you.',
      explanation:
        'In India\'s UPI architecture, receiving money is 100% automated—your bank account is credited directly without you ever scanning a QR code or entering your UPI PIN. Fraudsters deliberately invert this mechanic to trick sellers into authorizing an outgoing payment.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation,
      cybercrimeReportingNeeded: true,
      confidenceScore: 99,
    };
  }

  // Archetype B: Fake Bank KYC / YONO / Account Suspension Threat
  const mentionsBank = FUZZY_PATTERNS.bank_name.test(text) || /\b(bank|netbanking|credit\s*card)\b/i.test(text);
  const mentionsKyc = /\b(kyc|pan|pan\s*card|aadhaar|biometric)\b/i.test(text);
  const mentionsBlocked = hasTypoBlocked || /\b(blocked|deactivated|suspended|closed)\b/i.test(text);

  if ((mentionsBank || mentionsKyc) && mentionsBlocked && (hasAnyLink || hasApk || hasUrgency || hasTypoAccount)) {
    warningSigns.push('Threatens imminent account suspension or deactivation to induce panic.');
    if (hasAnyLink || hasApk) {
      warningSigns.push('Directs you to an unverified link or APK file to update confidential bank or KYC information.');
    }
    if (PHONE_NUMBER_PATTERN.test(text) && !OFFICIAL_BANK_DLT_HEADERS.test(text)) {
      warningSigns.push('Sent from a standard 10-digit mobile number rather than a verified TRAI DLT alphanumeric bank header (e.g. AX-SBIINB).');
    }

    recommendedActions.push('Do NOT click the link or download any .apk files.');
    recommendedActions.push('Do not share your PAN, Aadhaar, password, or OTP.');
    recommendedActions.push('Verify your account status by logging into your bank\'s official mobile application or visiting your branch.');
    recommendedActions.push('Report the fraudulent SMS to your bank and file a report on cybercrime.gov.in or call 1930.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Fake Bank KYC / Account Suspension Phishing',
      summary:
        'This is an aggressive phishing scam designed to steal your netbanking credentials and install malicious software on your device.',
      explanation:
        'Indian banks never send SMS messages threatening same-day account closure with external links or APK download prompts. Legitimate KYC updates can only be completed via the official bank app, netbanking portal, or physically at an authorized branch.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'Banks NEVER send SMS links or APK files to update KYC or reactivate accounts.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 98,
    };
  }

  // Archetype C: Electricity / Utility Power Disconnection Threat
  const mentionsPower = FUZZY_PATTERNS.power_cut.test(text);
  if (mentionsPower && (hasUrgency || /\b(officer|contact|call|bill|unpaid)\b/i.test(text))) {
    warningSigns.push('Manufactures extreme time pressure by threatening electricity disconnection at night (typically 9:30 PM).');
    warningSigns.push('Instructs you to contact a personal 10-digit mobile number instead of an official electricity board portal or counter.');
    warningSigns.push('Power utilities never send disconnection threats from personal numbers with requests to call individual agents.');

    recommendedActions.push('Do NOT call the phone number provided in the message.');
    recommendedActions.push('Check your electricity bill status directly on your official state electricity board app (e.g., BESCOM, TANGEDCO, MSEDCL, UPPCL) or payment app.');
    recommendedActions.push('Block the sender and report the number on the Chakshu portal (sancharsaathi.gov.in) and cybercrime.gov.in (1930).');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Urgent Electricity Bill Disconnection Extortion',
      summary:
        'This is a widespread utility extortion scam. Power utility boards never threaten immediate disconnection via SMS with personal phone numbers.',
      explanation:
        'Fraudsters use the panic of having your electricity cut off tonight to get you on the phone. Once on the call, they instruct you to download remote screen-sharing tools (like AnyDesk) or pay a nominal "reconnection fee" through a malicious link that drains your account.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'Never download remote-control apps or pay utility bills via personal numbers provided in text messages.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 99,
    };
  }

  // Archetype D: OTP / PIN Request Over Call or Text
  const asksForOtp = FUZZY_PATTERNS.otp.test(text);
  const mentionsFraudCell = /\b(fraud|unauthorized|international|charge|block\s*card|security\s*team)\b/i.test(text);

  if (asksForOtp && (mentionsFraudCell || mentionsBank || /\b(share|tell|give|cancel)\b/i.test(text))) {
    warningSigns.push('Explicitly requests a one-time password (OTP) or 6-digit verification code under the guise of "canceling" a transaction.');
    warningSigns.push('Genuine bank representatives NEVER request your OTP or PIN over phone calls, SMS, or WhatsApp.');

    recommendedActions.push('NEVER share your OTP, PIN, or CVV with anyone—including individuals claiming to be bank executives.');
    recommendedActions.push('Disconnect the call immediately.');
    recommendedActions.push('Call your bank\'s official customer care number (listed on the back of your debit card) to check for unauthorized activity.');
    recommendedActions.push('Call 1930 immediately if any unauthorized transaction has already occurred.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Bank Impersonation OTP Phishing Attack',
      summary:
        'This is a social engineering attack designed to steal your OTP to authorize an unauthorized debit or take over your netbanking account.',
      explanation:
        'Scammers fabricate a fake emergency—such as an unauthorized charge of ₹40,000+—to panic you into revealing the 6-digit OTP that arrived on your phone. Reading out this OTP authorizes the scammer to complete a fraudulent payment.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'No bank employee, RBI official, or police officer will EVER ask for your OTP or UPI PIN.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 99,
    };
  }

  // Archetype E: Fake PhonePe / GPay Cashback & Scratch Card Scam
  const mentionsReward = FUZZY_PATTERNS.cashback.test(text) || FUZZY_PATTERNS.lottery.test(text);
  if (mentionsReward && (hasAnyLink || /\b(congratulation|won|claim|lakh|crore|kbc)\b/i.test(text))) {
    warningSigns.push('Offers unrealistic cashback (e.g. ₹4,999) or lottery prizes to entice you to click third-party links.');
    warningSigns.push('Cashback in official apps (PhonePe, Google Pay, Paytm) is credited automatically without clicking external web links.');
    if (hasAnyLink) {
      warningSigns.push('Link directs to an unauthorized domain mimicking official payment application branding.');
    }

    recommendedActions.push('Do NOT click the reward or scratch card link.');
    recommendedActions.push('Never enter your UPI PIN or bank details to claim cashback or rewards.');
    recommendedActions.push('Check the Rewards section directly inside your official PhonePe or Google Pay app.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Fake Payment App Cashback & Scratch Card Phishing',
      summary:
        'This is a fake cashback lure designed to trick you into approving a UPI collect request or entering credentials on a fraudulent website.',
      explanation:
        'Official UPI payment applications credit cashback directly into your linked bank account. They never send SMS or WhatsApp messages containing external links to "claim" or "redeem" cash prizes.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'Legitimate cashback is credited automatically without entering a PIN or clicking external redemption links.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 98,
    };
  }

  // Archetype F: Fake Work From Home / YouTube Like Task Scam
  const mentionsJob = FUZZY_PATTERNS.job_task.test(text);
  if (mentionsJob && (/\b(earn|daily|2000|5000|telegram|whatsapp|task)\b/i.test(text) || hasAnyLink)) {
    warningSigns.push('Promises exorbitant daily earnings (₹2,000–₹5,000) for trivial tasks like liking YouTube videos or rating Google Maps.');
    warningSigns.push('Operates through encrypted chat apps (Telegram, WhatsApp) without legitimate corporate registration.');
    warningSigns.push('Classic prepaid task scam structure: initial small payouts followed by demands for heavy "VIP deposits".');

    recommendedActions.push('Do NOT contact the recruiter or join the Telegram/WhatsApp group.');
    recommendedActions.push('Never send money or "processing fees" to unlock tasks or withdraw earnings.');
    recommendedActions.push('Report the recruiter account and phone number on the Chakshu portal (sancharsaathi.gov.in).');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Part-Time Task & YouTube Like Employment Fraud',
      summary:
        'This is a classic prepaid task scam. Initial tiny payouts are used as bait before victims are tricked into sending lakhs for "VIP crypto tiers".',
      explanation:
        'Fraud syndicates recruit via WhatsApp and Telegram, offering money for simple tasks. Once the victim is hooked and attempts to withdraw accumulated "earnings", the scammers demand thousands of rupees in taxes and clearance fees before vanishing.',
      warningSigns,
      recommendedActions,
      confidenceScore: 98,
      cybercrimeReportingNeeded: true,
    };
  }

  // Archetype G: Remote Access Application (AnyDesk, TeamViewer)
  const mentionsRemote = FUZZY_PATTERNS.remote_app.test(text);
  if (mentionsRemote && (mentionsBank || mentionsKyc || /\b(support|install|download|help|agent)\b/i.test(text))) {
    warningSigns.push('Instructs you to install a remote desktop screen-sharing application (AnyDesk, TeamViewer, RustDesk).');
    warningSigns.push('Allows the scammer to view your phone screen live and intercept OTPs, passwords, and banking sessions.');

    recommendedActions.push('Do NOT install any screen-sharing application.');
    recommendedActions.push('If already installed, immediately uninstall it and turn off your phone\'s Wi-Fi and mobile data.');
    recommendedActions.push('Call your bank to freeze netbanking and UPI access immediately.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Remote Desktop Screen-Sharing Takeover Scam',
      summary:
        'This is a device takeover attack. Installing screen-sharing apps gives fraudsters total visibility over your screen, OTPs, and passwords.',
      explanation:
        'Customer support agents and bank staff will NEVER ask customers to install remote access tools like AnyDesk or RustDesk. Once installed, scammers watch your screen in real time while initiating transfers.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'Never install remote screen-sharing tools on instructions from unverified callers.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 99,
    };
  }

  // Archetype H: Legitimate Bank Alert Pattern Matching
  const hasCreditOrDebit = /\b(credited\s*with|debited\s*with|withdrawn|spent|txn\s*of)\b/i.test(text);
  const hasAmount = /\b(inr|rs\.?|₹)\s*[\d,]+(\.\d{2})?\b/i.test(text);
  const hasBalance = /\b(bal|balance|total\s*bal|avbl\s*bal)\b/i.test(text);
  const hasRefNo = /\b(ref|upi\/p2[ap]|rrn|utr|txn\s*id)\b/i.test(text);
  const hasDisputeBlock = /\b(if\s*not\s*done\s*by\s*you|sms\s*block|call\s*1800|not\s*you\?)\b/i.test(text);

  if (hasCreditOrDebit && hasAmount && (hasBalance || hasRefNo) && !hasAnyLink && !hasApk && !mentionsPin && !mentionsQr) {
    warningSigns.push('Matches the standard transaction notification template prescribed by the Reserve Bank of India.');
    warningSigns.push('Contains structured reference numbers, masked account identifier, and official dispute instructions.');
    warningSigns.push('Contains no external URLs, no requests to download files, and no solicitations for OTP or PIN.');

    recommendedActions.push('Verify the transaction directly inside your official bank mobile application or netbanking portal.');
    recommendedActions.push('If this transaction was not performed by you, use the official dispute number or SMS block code immediately.');
    recommendedActions.push('Never forward your transaction SMS or OTP to anyone.');

    return {
      verdict: 'LIKELY LEGITIMATE',
      riskLevel: 'LOW',
      scamType: 'Authentic Bank Transaction Notification',
      summary:
        'This message follows the standard template of genuine Indian banking transaction alerts. However, always cross-verify transactions directly in your bank app.',
      explanation:
        'The notification uses official terminology, includes transaction reference numbers and masked account digits, and does not pressure you with malicious links or requests for confidential information. (Note: No communication can be guaranteed 100% immune from spoofing—always verify in your official app).',
      warningSigns,
      recommendedActions,
      confidenceScore: 94,
    };
  }

  // Archetype I: Hinglish Colloquial Lottery / Family Emergency
  const isHinglishScam =
    /\b(bhai|yaar|badhai|nikla|jeete|rupaye|bhej\s*do|paisa|turant)\b/i.test(text) &&
    (mentionsReward || mentionsPin || mentionsQr || hasAnyLink || /\b(tax|charge|fee)\b/i.test(text));

  if (isHinglishScam) {
    warningSigns.push('Uses informal Hinglish slang combined with prize claims or urgent money transfer demands.');
    warningSigns.push('Demands an upfront "registration fee" or "tax" to release a promised sum (advance-fee fraud).');

    recommendedActions.push('Do NOT transfer any money or scan QR codes.');
    recommendedActions.push('Block the contact on WhatsApp or SMS.');
    recommendedActions.push('Report the scammer\'s number to 1930.');

    return {
      verdict: 'LIKELY SCAM',
      riskLevel: 'CRITICAL',
      scamType: 'Hinglish Advance-Fee Lottery & Reward Scam',
      summary:
        'This is advance-fee fraud communicated in casual Hinglish. Any request to pay money or scan a QR code to "release" winnings is a scam.',
      explanation:
        'Scammers use everyday colloquial language to make prizes feel genuine. Asking for a small "processing fee" or "advance tax" is the core hallmark of lottery fraud.',
      warningSigns,
      recommendedActions,
      goldenRuleViolation: 'You never pay money, fees, or taxes to receive legitimate prize winnings or lottery payouts.',
      cybercrimeReportingNeeded: true,
      confidenceScore: 98,
    };
  }

  // Archetype J: Generic Suspicious or Ambiguous Input
  if (hasAnyLink || hasUrgency || mentionsBank || mentionsPin || mentionsQr) {
    warningSigns.push('Contains elements often associated with payment scams (links, urgency, or mentions of sensitive payment flows).');
    warningSigns.push('Lacks complete context to confirm authenticity with absolute certainty.');

    recommendedActions.push('Exercise high caution. Do not click links or share confidential information.');
    recommendedActions.push('Verify the identity of the sender through official channels before proceeding.');
    recommendedActions.push('If unsure, contact your bank\'s customer care or call 1930.');

    return {
      verdict: 'SUSPICIOUS',
      riskLevel: 'MEDIUM',
      scamType: 'Unverified Communication with High-Risk Elements',
      summary:
        'This message contains risk factors such as unverified links or urgency. Exercise extreme caution and do not share any credentials.',
      explanation:
        'While the message may not match a single known scam pattern with 100% certainty, it exhibits indicators like unverified web links, requests for interaction, or artificial urgency that require careful validation.',
      warningSigns,
      recommendedActions,
      confidenceScore: 82,
    };
  }

  // Default: Uncertain
  return {
    verdict: 'UNCERTAIN',
    riskLevel: 'LOW',
    scamType: 'Unclassified Message / Low Context',
    summary:
      'The provided text does not contain typical payment scam markers or verified banking patterns. Please provide more context if this involves a transaction.',
    explanation:
      'We could not identify clear indicators of fraud, phishing, or official financial notifications. If this message is connected to a payment request, classifieds sale, or caller asking for money, paste the full conversation for detailed analysis.',
    warningSigns: [
      'Insufficient specific markers (no identifiable payment links, QR codes, or financial requests detected)',
    ],
    recommendedActions: [
      'If this communication asks for payment or personal details later, re-scan the message here.',
      'Remember the golden rule: Never enter your UPI PIN to receive money.',
    ],
    confidenceScore: 70,
  };
}
