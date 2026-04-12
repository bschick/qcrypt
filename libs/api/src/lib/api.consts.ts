/* MIT License

Copyright (c) 2024-2026 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

export const TOPICID_BYTES = 16;
export const DESC_LEN_BYTES = 1;
export const DESC_MAX_BYTES = 255;

export const TOPIC_MAX_BYTES = TOPICID_BYTES + DESC_LEN_BYTES + DESC_MAX_BYTES + SIG_CERT_MAX_BYTES + KEM_CERT_MAX_BYTES + MAX_TOPIC_MESSAGES_BYTES + TIMESTAMP_BYTES + LADDER_LEN_BYTES + LADDER_MAX_BYTES;
