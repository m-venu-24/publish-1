export interface FeedbackRecord {
  timestamp: string;
  content: string;
  content_type: string;
  predicted_label: string;
  user_label: string;
  findings_count: number;
  risk_level: string;
  finding_types: string[];
}

export interface WhitelistRecord {
  domain: string;
  added_at: string;
  reason?: string;
}

export class FeedbackManager {
  private feedbackList: FeedbackRecord[] = [];
  private whitelist: WhitelistRecord[] = [];

  addFeedback(data: {
    content: string;
    content_type: string;
    predicted_label: string;
    user_label: string;
    findings: any[];
    risk_level: string;
  }): FeedbackRecord {
    const record: FeedbackRecord = {
      timestamp: new Date().toISOString(),
      content: (data.content || "").slice(0, 500),
      content_type: data.content_type,
      predicted_label: data.predicted_label,
      user_label: data.user_label,
      findings_count: data.findings.length,
      risk_level: data.risk_level,
      finding_types: data.findings.map((f) => f.type),
    };
    this.feedbackList.push(record);
    return record;
  }

  addToWhitelist(domain: string, reason: string = ""): { domain?: string; error?: string } {
    const d = domain.trim().toLowerCase();
    if (this.whitelist.some((w) => w.domain === d)) {
      return { error: "Domain already whitelisted" };
    }
    const record: WhitelistRecord = {
      domain: d,
      added_at: new Date().toISOString(),
      reason,
    };
    this.whitelist.push(record);
    return { domain: d };
  }

  removeFromWhitelist(domain: string): boolean {
    const d = domain.trim().toLowerCase();
    const idx = this.whitelist.findIndex((w) => w.domain === d);
    if (idx !== -1) {
      this.whitelist.splice(idx, 1);
      return true;
    }
    return false;
  }

  isWhitelisted(domain: string): boolean {
    const d = domain.trim().toLowerCase();
    return this.whitelist.some((w) => w.domain === d);
  }

  getWhitelist(): WhitelistRecord[] {
    return [...this.whitelist];
  }

  getFeedbackStats(): Record<string, any> {
    const total = this.feedbackList.length;
    if (total === 0) {
      return { total: 0, false_positives: 0, false_negatives: 0 };
    }
    const falsePositives = this.feedbackList.filter(
      (f) => f.predicted_label === "phishing" && f.user_label === "legitimate"
    ).length;
    const falseNegatives = this.feedbackList.filter(
      (f) => f.predicted_label === "legitimate" && f.user_label === "phishing"
    ).length;

    return {
      total,
      false_positives: falsePositives,
      false_negatives: falseNegatives,
      false_positive_rate: total > 0 ? falsePositives / total : 0,
      false_negative_rate: total > 0 ? falseNegatives / total : 0,
    };
  }
}

let feedbackManagerInstance: FeedbackManager | null = null;

export function getFeedbackManager(): FeedbackManager {
  if (!feedbackManagerInstance) {
    feedbackManagerInstance = new FeedbackManager();
  }
  return feedbackManagerInstance;
}
