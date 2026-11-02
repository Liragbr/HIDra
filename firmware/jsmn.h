/*
 * jsmn.h — Minimalistic JSON parser
 * https://github.com/zserge/jsmn
 *
 * MIT License
 * Copyright (c) 2010 Serge Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef JSMN_H
#define JSMN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* JSON token types */
typedef enum {
    JSMN_UNDEFINED = 0,
    JSMN_OBJECT    = 1,
    JSMN_ARRAY     = 2,
    JSMN_STRING    = 3,
    JSMN_PRIMITIVE = 4,  /* number, boolean, null */
} jsmntype_t;

typedef enum {
    JSMN_ERROR_NOMEM = -1,  /* not enough tokens were provided */
    JSMN_ERROR_INVAL = -2,  /* invalid character inside JSON string */
    JSMN_ERROR_PART  = -3,  /* the string is not a full JSON packet */
} jsmnerr_t;

typedef struct jsmntok {
    jsmntype_t type;
    int        start;  /* start position in JSON data string */
    int        end;    /* end   position in JSON data string */
    int        size;   /* number of children                 */
} jsmntok_t;

typedef struct jsmn_parser {
    unsigned int pos;      /* offset in the JSON string */
    unsigned int toknext;  /* next token to allocate    */
    int          toksuper; /* superior token node, e.g. parent object or array */
} jsmn_parser;

void jsmn_init(jsmn_parser *parser);

int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens);

#ifdef __cplusplus
}
#endif

/* ── Implementation (compiled only when JSMN_IMPLEMENTATION is defined) ── */
#ifdef JSMN_IMPLEMENTATION

static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser,
                                    jsmntok_t   *tokens,
                                    size_t        num_tokens) {
    if (parser->toknext >= num_tokens) return NULL;
    jsmntok_t *tok  = &tokens[parser->toknext++];
    tok->start = tok->end = -1;
    tok->size  = 0;
    return tok;
}

static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type,
                              int start, int end) {
    token->type  = type;
    token->start = start;
    token->end   = end;
    token->size  = 0;
}

static int jsmn_parse_primitive(jsmn_parser *parser, const char *js,
                                  size_t len, jsmntok_t *tokens,
                                  size_t num_tokens) {
    int start = (int)parser->pos;
    for (; parser->pos < len; parser->pos++) {
        char c = js[parser->pos];
        switch (c) {
        case ':': case ',': case ']': case '}': case ' ':
        case '\t': case '\r': case '\n':
            goto found;
        default:
            if (c < 32 || c >= 127) return JSMN_ERROR_INVAL;
        }
    }
found:
    if (tokens) {
        jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
        if (!token) return JSMN_ERROR_NOMEM;
        jsmn_fill_token(token, JSMN_PRIMITIVE, start, (int)parser->pos);
        token->size = 0;
    }
    parser->pos--;
    return 0;
}

static int jsmn_parse_string(jsmn_parser *parser, const char *js,
                               size_t len, jsmntok_t *tokens,
                               size_t num_tokens) {
    int start = (int)parser->pos++;
    for (; parser->pos < len; parser->pos++) {
        char c = js[parser->pos];
        if (c == '\"') {
            if (tokens) {
                jsmntok_t *token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (!token) return JSMN_ERROR_NOMEM;
                jsmn_fill_token(token, JSMN_STRING, start + 1, (int)parser->pos);
            }
            return 0;
        }
        if (c == '\\' && parser->pos + 1 < len) {
            parser->pos++;
            switch (js[parser->pos]) {
            case '\"': case '/': case '\\': case 'b':
            case 'f':  case 'r': case 'n':  case 't': break;
            case 'u':
                parser->pos++;
                for (int i = 0; i < 4 && parser->pos < len; i++, parser->pos++) {
                    char h = js[parser->pos];
                    if (!((h >= '0' && h <= '9') || (h >= 'A' && h <= 'F') ||
                          (h >= 'a' && h <= 'f')))
                        return JSMN_ERROR_INVAL;
                }
                parser->pos--;
                break;
            default: return JSMN_ERROR_INVAL;
            }
        }
    }
    return JSMN_ERROR_PART;
}

void jsmn_init(jsmn_parser *parser) {
    parser->pos      = 0;
    parser->toknext  = 0;
    parser->toksuper = -1;
}

int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
               jsmntok_t *tokens, unsigned int num_tokens) {
    int        r;
    int        i;
    jsmntok_t *token;
    int        count = (int)parser->toknext;

    for (; parser->pos < len; parser->pos++) {
        char       c    = js[parser->pos];
        jsmntype_t type;

        switch (c) {
        case '{': case '[':
            count++;
            if (!tokens) break;
            token = jsmn_alloc_token(parser, tokens, num_tokens);
            if (!token) return JSMN_ERROR_NOMEM;
            if (parser->toksuper != -1) {
                jsmntok_t *t = &tokens[parser->toksuper];
                t->size++;
            }
            token->type  = (c == '{') ? JSMN_OBJECT : JSMN_ARRAY;
            token->start = (int)parser->pos;
            parser->toksuper = (int)(parser->toknext - 1);
            break;

        case '}': case ']':
            if (!tokens) break;
            type = (c == '}') ? JSMN_OBJECT : JSMN_ARRAY;
            for (i = (int)parser->toknext - 1; i >= 0; i--) {
                token = &tokens[i];
                if (token->start != -1 && token->end == -1) {
                    if (token->type != type) return JSMN_ERROR_INVAL;
                    parser->toksuper = -1;
                    token->end = (int)parser->pos + 1;
                    break;
                }
            }
            if (i == -1) return JSMN_ERROR_INVAL;
            for (; i >= 0; i--) {
                token = &tokens[i];
                if (token->start != -1 && token->end == -1) {
                    parser->toksuper = i;
                    break;
                }
            }
            break;

        case '\"':
            r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
            if (r < 0) return r;
            count++;
            if (parser->toksuper != -1 && tokens)
                tokens[parser->toksuper].size++;
            break;

        case '\t': case '\r': case '\n': case ' ': break;

        case ':':
            parser->toksuper = (int)parser->toknext - 1;
            break;

        case ',':
            if (tokens && parser->toksuper != -1) {
                jsmntype_t st = tokens[parser->toksuper].type;
                if (st != JSMN_ARRAY && st != JSMN_OBJECT) {
                    for (i = (int)parser->toknext - 1; i >= 0; i--) {
                        if (tokens[i].type == JSMN_ARRAY ||
                            tokens[i].type == JSMN_OBJECT) {
                            if (tokens[i].start != -1 && tokens[i].end == -1) {
                                parser->toksuper = i;
                                break;
                            }
                        }
                    }
                }
            }
            break;

        default:
            r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
            if (r < 0) return r;
            count++;
            if (parser->toksuper != -1 && tokens)
                tokens[parser->toksuper].size++;
            break;
        }
    }

    if (tokens) {
        for (i = (int)parser->toknext - 1; i >= 0; i--) {
            if (tokens[i].start != -1 && tokens[i].end == -1)
                return JSMN_ERROR_PART;
        }
    }
    return count;
}

#endif /* JSMN_IMPLEMENTATION */
#endif /* JSMN_H */
