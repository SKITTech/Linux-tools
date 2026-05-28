export type AskMode = "beginner" | "advanced";

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: number;
}

export type Level = "beginner" | "intermediate" | "advanced";

export interface Lesson {
  id: string;
  title: string;
  level: Level;
  summary: string;
  body: string; // markdown
  tryIt: string[]; // commands
  mistakes: string[];
  checkpoints: { q: string; choices: string[]; answer: number; explain: string }[];
}

export type QType = "single" | "multi" | "command";

export interface QuizQuestion {
  id: string;
  level: Level;
  topic: string;
  type: QType;
  q: string;
  choices: string[];
  answer: number | number[]; // index, or indices for multi
  explain: string;
}

export interface QuizProgress {
  scoreById: Record<string, { correct: number; wrong: number; lastSeen: number; nextDue: number }>;
  streak: number;
  totalCorrect: number;
  totalAnswered: number;
}
