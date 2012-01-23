-- Stolen from yesod-auth.
--
-- CPP macro which choses which quasyquotes syntax to use depending
-- on GHC version.
--
-- QQ stands for quasiquote.
#if GHC7
# define QQ(x) x
#else
# define QQ(x) $x
#endif
