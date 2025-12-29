- All comments must be written in the // style, no /* */

- All comments must be in short statements and more in a common speaking language, not scientific.

- All one line if(), for() and while() statements must be in the fillowing style:
if condition
{
    code;
}

- Make sure all return, continue and break statements has an empty line above them, unless they are in a single block

- Keep every statement on 1 line, unless the line goes above like 100 characters, then make new lines

- Header files needs to use #pragma once

- All variables should be full name, for example, no, int w; but int width;, however 'char c' is fine to use, also i, j, k, l, n, m, is fine to use for nested loops, unless it is needed to be specific about what the index really is, then it should use a proper name.

- When using registers, use the proper register names for variables, like eax, not eax_value or something else.

- Do not try to align variables with tabs, like char<tab>var_name;, just do char var_name; no tabs or extensive spacing.

- All code must have room between the blocks, like this:
code;

if condition
{
    code;
}

code;

- All comments need to be in english

- Do not summarize anything in the comments like "Im adding comments in english", etc.

- If you find code that you are not sure how to comment, you ask me.

- No periods in comments, unless it is needed to use more than 1 sentence in the comment
