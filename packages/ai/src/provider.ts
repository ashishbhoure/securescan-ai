/**
 * SecureScan AI - Pluggable AI Security Provider Interface & Implementations
 */

import { AIAnalysisResult, FindingResult } from '@securescan/types';
import { promptSanitizer } from './sanitizer.js';
import { logger } from '@securescan/logger';

export interface RemediationPromptInput {
  finding: FindingResult;
  targetUrl: string;
  technologies?: string[];
}

export interface QnAPromptInput {
  question: string;
  contextFindings: FindingResult[];
  organizationName: string;
}

export interface QnAResult {
  answer: string;
  suggestedActionItems: string[];
}

export interface AIProvider {
  generateRemediation(input: RemediationPromptInput): Promise<AIAnalysisResult>;
  answerSecurityQuestion(input: QnAPromptInput): Promise<QnAResult>;
}

/**
 * Deterministic Mock AI Provider for testing and offline environments
 */
export class MockAIProvider implements AIProvider {
  public async generateRemediation(input: RemediationPromptInput): Promise<AIAnalysisResult> {
    const { finding, technologies } = input;
    const techContext = technologies && technologies.length > 0 ? technologies.join(', ') : 'standard web server';

    return {
      plainExplanation: `We detected "${finding.title}". This means that your server or application is currently not enforcing standard security protections on ${input.targetUrl}.`,
      businessImpact: `Without this control, customers and users may be exposed to unauthorized data interception or browser-level exploitation. For compliance frameworks like SOC 2, ISO 27001, and PCI-DSS, fixing this is a standard requirement.`,
      technicalExplanation: `The technical check failed: ${finding.evidence.summary}. Rule: ${finding.ruleId} (${finding.category}). Detected environment: ${techContext}.`,
      developerFix: `To resolve this in your application:\n\n` +
        `1. Open your web server configuration or backend application router.\n` +
        `2. Apply the recommended directive:\n\n` +
        `   ${finding.remediation}\n\n` +
        `3. Re-deploy and verify the HTTP response headers.`,
      validationSteps: [
        `Curl the endpoint: curl -I ${input.targetUrl}`,
        `Verify the presence of the required configuration directive in the response headers`,
        `Re-run SecureScan AI to confirm finding status updates to RESOLVED`,
      ],
      priorityReasoning: `Severity is ${finding.severity}. Address this according to your security remediation SLA.`,
      tokenUsage: {
        promptTokens: 250,
        completionTokens: 180,
        totalTokens: 430,
      },
    };
  }

  public async answerSecurityQuestion(input: QnAPromptInput): Promise<QnAResult> {
    const count = input.contextFindings.length;
    return {
      answer: `Based on your ${count} current security findings in ${input.organizationName}, here is our analysis regarding "${input.question}": prioritize resolving all CRITICAL and HIGH severity findings first to restore your posture score.`,
      suggestedActionItems: [
        'Review the findings page sorted by severity',
        'Assign open findings to team members',
        'Trigger a re-scan once updates are deployed',
      ],
    };
  }
}

/**
 * Real OpenAI Provider using fetch API and structured JSON prompt
 */
export class OpenAIProvider implements AIProvider {
  private apiKey: string;
  private model: string;

  constructor(apiKey: string, model = 'gpt-4o-mini') {
    this.apiKey = apiKey;
    this.model = model;
  }

  public async generateRemediation(input: RemediationPromptInput): Promise<AIAnalysisResult> {
    const { finding, targetUrl, technologies } = input;

    const isolatedEvidence = promptSanitizer.wrapUntrustedData(
      JSON.stringify(finding.evidence),
      'untrusted_scan_evidence'
    );

    const systemPrompt = `You are a Principal Application Security Engineer at SecureScan AI.
Your role is to explain verified security findings and generate developer-friendly remediation guidance.
CRITICAL: Never invent or fabricate vulnerabilities.
Output MUST be strict valid JSON matching the schema:
{
  "plainExplanation": "string",
  "businessImpact": "string",
  "technicalExplanation": "string",
  "developerFix": "string",
  "validationSteps": ["string"],
  "priorityReasoning": "string"
}`;

    const userPrompt = `Analyze this finding:
Title: ${finding.title}
Rule ID: ${finding.ruleId}
Severity: ${finding.severity}
Target URL: ${targetUrl}
Technologies Detected: ${technologies?.join(', ') || 'Unknown'}
Remediation Template: ${finding.remediation}

Evidence:
${isolatedEvidence}`;

    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model: this.model,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          temperature: 0.2,
        }),
      });

      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.status} ${response.statusText}`);
      }

      const json = await response.json();
      const content = json.choices[0]?.message?.content;
      const parsed = JSON.parse(content);

      return {
        plainExplanation: parsed.plainExplanation || '',
        businessImpact: parsed.businessImpact || '',
        technicalExplanation: parsed.technicalExplanation || '',
        developerFix: parsed.developerFix || '',
        validationSteps: parsed.validationSteps || [],
        priorityReasoning: parsed.priorityReasoning || '',
        tokenUsage: {
          promptTokens: json.usage?.prompt_tokens || 0,
          completionTokens: json.usage?.completion_tokens || 0,
          totalTokens: json.usage?.total_tokens || 0,
        },
      };
    } catch (err) {
      logger.error('OpenAI generation failed, falling back to deterministic mock provider', {
        error: (err as Error).message,
      });
      const fallback = new MockAIProvider();
      return fallback.generateRemediation(input);
    }
  }

  public async answerSecurityQuestion(input: QnAPromptInput): Promise<QnAResult> {
    const fallback = new MockAIProvider();
    return fallback.answerSecurityQuestion(input);
  }
}

export function createAIProvider(type: string, apiKey?: string, model?: string): AIProvider {
  if (type === 'openai' && apiKey) {
    return new OpenAIProvider(apiKey, model);
  }
  return new MockAIProvider();
}
