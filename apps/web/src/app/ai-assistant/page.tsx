'use client';

import React, { useState } from 'react';
import { AppLayout } from '../../components/layout/AppLayout';
import { api } from '../../lib/api';

export default function AIAssistantPage() {
  const [question, setQuestion] = useState('');
  const [conversation, setConversation] = useState<
    { sender: 'user' | 'ai'; text: string; actionItems?: string[] }[]
  >([
    {
      sender: 'ai',
      text: 'Hello! I am your SecureScan AI Security Analyst. I can explain your organization\'s vulnerabilities, suggest priority fixes, and generate custom code patches for your web server or framework. How can I assist with your posture today?',
    },
  ]);
  const [loading, setLoading] = useState(false);

  const handleAsk = async (queryText?: string) => {
    const q = queryText || question;
    if (!q.trim() || loading) return;

    setConversation((prev) => [...prev, { sender: 'user', text: q }]);
    setQuestion('');
    setLoading(true);

    try {
      const res = await api.askSecurityAI(q);
      setConversation((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: res.qna.answer,
          actionItems: res.qna.suggestedActionItems,
        },
      ]);
    } catch (err) {
      setConversation((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: `Error analyzing request: ${(err as Error).message}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const samplePrompts = [
    'What vulnerability should our engineering team fix first?',
    'Why is our overall security score penalized?',
    'How do I configure Strict-Transport-Security in Nginx?',
    'Provide a prioritized remediation checklist for our sprint.',
  ];

  return (
    <AppLayout>
      <div className="space-y-6 max-w-4xl mx-auto flex flex-col h-[calc(100vh-10rem)]">
        <div>
          <h1 className="text-2xl font-black text-white tracking-tight">AI Security Analyst</h1>
          <p className="text-sm text-gray-400 mt-1">
            Contextual security intelligence grounded exclusively in your verified scan findings.
          </p>
        </div>

        {/* Chat Stream */}
        <div className="flex-1 bg-surface border border-border rounded-2xl p-6 overflow-y-auto space-y-4">
          {conversation.map((msg, idx) => (
            <div
              key={idx}
              className={`flex items-start space-x-3 ${
                msg.sender === 'user' ? 'justify-end' : 'justify-start'
              }`}
            >
              {msg.sender === 'ai' && (
                <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-sm shrink-0">
                  🤖
                </div>
              )}

              <div
                className={`max-w-xl p-4 rounded-2xl text-sm leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-cyan-500 text-gray-950 font-medium rounded-tr-none'
                    : 'bg-card border border-border text-gray-200 rounded-tl-none'
                }`}
              >
                <p className="whitespace-pre-wrap">{msg.text}</p>

                {msg.actionItems && msg.actionItems.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border/60">
                    <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 block mb-1">
                      Action Items:
                    </span>
                    <ul className="text-xs space-y-1 list-disc list-inside text-gray-300">
                      {msg.actionItems.map((item, i) => (
                        <li key={i}>{item}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ))}

          {loading && (
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 text-sm">
                🤖
              </div>
              <div className="p-3 bg-card rounded-2xl rounded-tl-none border border-border text-xs text-cyan-400 animate-pulse">
                Analyzing verified scan evidence...
              </div>
            </div>
          )}
        </div>

        {/* Prompt Suggestions */}
        <div className="flex flex-wrap gap-2">
          {samplePrompts.map((p, idx) => (
            <button
              key={idx}
              onClick={() => handleAsk(p)}
              className="text-xs bg-card hover:bg-border/60 border border-border text-gray-300 px-3 py-1.5 rounded-lg transition-colors truncate max-w-xs"
            >
              💡 {p}
            </button>
          ))}
        </div>

        {/* Query Input */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleAsk();
          }}
          className="flex items-center space-x-3"
        >
          <input
            type="text"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Ask a question about your security posture, rules, or fixes..."
            className="flex-1 px-4 py-3 rounded-xl bg-surface border border-border text-white text-sm focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="px-6 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-gray-950 text-sm font-bold rounded-xl transition-colors shadow-lg shadow-cyan-500/20"
          >
            Ask AI
          </button>
        </form>
      </div>
    </AppLayout>
  );
}
