#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include "config.h"
#include "pwstr.h"

/*
   Rule configuration structure
*/

#define RULE_T_NONE          0
#define RULE_T_LESS          1	/* <  */
#define RULE_T_LESS_EQUAL    2  /* <= */
#define RULE_T_EQUAL         3  /* =  */
#define RULE_T_GREATER       4  /* >  */
#define RULE_T_GREATER_EQUAL 5  /* >= */

typedef struct __rule_ {
   int test;				/* Test to perform 				*/
   double value;				/* Value that triggers the rule */
} rule_t;

static char rule_desc[512] = { 0 };
static int rule_ret = 0, rules_loaded = 0;
static rule_t rule_alpha, rule_alphadelta, rule_numeric, rule_other, rule_length, *rule_last = NULL;

/*
   Load password strength rules from a file
*/

static int load_rules(const char *filename)
{
   int test = RULE_T_NONE;
   rule_t *r = NULL;
   FILE *stream = NULL;
   char b[1024] = { 0 }, *t = NULL, *v = NULL, *p = NULL;

   /*
	  Reset rules
   */

   rule_ret = 0;
   rule_last = NULL;

   memset(rule_desc, 0, sizeof(rule_desc));

   memset(&rule_alpha, 0, sizeof(rule_alpha));
   memset(&rule_alphadelta, 0, sizeof(rule_alphadelta));
   memset(&rule_numeric, 0, sizeof(rule_numeric));
   memset(&rule_other, 0, sizeof(rule_other));
   memset(&rule_length, 0, sizeof(rule_length));

   /*
	  Open rules configuration
   */

   stream = fopen(filename, "r");
   if (stream == NULL) {
	  if (errno != ENOENT) {
		 fprintf(stderr,"load_rules: %s: %s\n", filename, strerror(errno));
		 return 0;
	  }

	  return 1;
   }

   /*
	  Loop through configurations
   */

   while(!(feof(stream))) {
	  memset(b, 0, sizeof(b));
	  fgets(b, sizeof(b), stream);

	  /*
		 Cut off comments and newlines
	  */

	  for (p = b; *p; p++) {
		 if ((*p == '#') || (*p == '\r') || (*p == '\n')) {
			*p = '\0';
			break;
		 }
	  }

	  /*
		 Skip comment lines
	  */

	  if (!(*b))
		 continue;

	  /*
		 Find name/test separator
	  */

	  for (t = b; *t; t++) {
		 if ((*t == ' ') || (*t == '\t')) {
			*t++ = '\0';
			while ((*t == ' ') || (*t == '\t')) t++;

			break;
		 }
	  }

	  if (!(*t)) {
		 fprintf(stderr,"load_rules: %s: syntax error: %s\n", filename, b);
		 continue;
	  }

	  /*
		 Find test/value seperator
	  */

	  for (v = t; *v; v++) {
		 if ((*v == ' ') || (*v == '\t')) {
			*v++ = '\0';
			while ((*v == ' ') || (*v == '\t')) v++;

			break;
		 }
	  }

	  if (!(*v)) {
		 fprintf(stderr,"load_rules: %s: syntax error: %s\n", filename, b);
		 continue;
	  }

	  /*
		 If setting policy description, save it and move on
	  */

	  if (!(strcasecmp(b, "policy"))) {
		 snprintf(rule_desc, sizeof(rule_desc), "%s", v);
		 continue;
	  }

	  /*
		 Cut off any extra whitespace
	  */

	  for (p = v; *p; p++) {
		 if ((*p == ' ') || (*p == '\t')) {
			*p = '\0';
			break;
		 }
	  }

	  /*
		 Point to appropriate rule structure
	  */

	  r = NULL;

	  if (!strcasecmp(b, "alphabet"))        r = &rule_alpha;
	  else if (!strcasecmp(b, "upperlower")) r = &rule_alphadelta;
	  else if (!strcasecmp(b, "numeric"))    r = &rule_numeric;
	  else if (!strcasecmp(b, "other"))      r = &rule_other;
	  else if (!strcasecmp(b, "length"))     r = &rule_length;

	  else {
		 fprintf(stderr,"load_rules: %s: unknown rule: %s\n", filename, b);
		 fclose(stream);
		 return 0;
	  }

	  /*
		 Determine test type
	  */

	  if (!strcasecmp(t, "<"))       test = RULE_T_LESS;
	  else if (!strcasecmp(t, "<=")) test = RULE_T_LESS_EQUAL;
	  else if (!strcasecmp(t, "="))  test = RULE_T_EQUAL;
	  else if (!strcasecmp(t, ">"))  test = RULE_T_GREATER;
	  else if (!strcasecmp(t, ">=")) test = RULE_T_GREATER_EQUAL;

	  else {
		 fprintf(stderr,"load_rules: %s: invalid test: %s\n", filename, t);
		 fclose(stream);
		 return 0;
	  }

	  /*
		 Set rule
	  */

	  r->test = test;
	  r->value = strtod(v, NULL);
   }

   fclose(stream);
   return 1;
}

/*
   Returns if a rule evalutes as true
*/

static int rule_is_true(rule_t *r, double value)
{
   /*
	  Default to true
   */

   rule_ret = 1;
   rule_last = NULL;

   /*
	  No rule is always true
   */

   if (r == NULL) return 1;

   /*
	  Save last rule checked
   */

   rule_last = r;

   /*
	  Test
   */

   switch(r->test) {
	  case RULE_T_LESS:
		 rule_ret = (value < r->value);
		 break;

	  case RULE_T_LESS_EQUAL:
		 rule_ret = (value <= r->value);
		 break;

	  case RULE_T_EQUAL:
		 rule_ret = (value == r->value);
		 break;

	  case RULE_T_GREATER:
		 rule_ret = (value > r->value);
		 break;

	  case RULE_T_GREATER_EQUAL:
		 rule_ret = (value >= r->value);
		 break;

	  /*
		 No rule, or an unknown test, always evaluate true
	  */

	  default:
		 rule_ret = 1;
		 break;
   };

   return rule_ret;
}

/*
   Check password strength matches rules
*/

int pw_strength(const char *password)
{
   char b[512] = { 0 };
   const char *p = NULL;
   double len = 0, score = 0, n_lower = 0, n_upper = 0, n_numeric = 0, n_other = 0, n_alpha = 0;
   double r_lower = 0, r_upper = 0, r_numeric = 0, r_other = 0, r_alpha = 0;
   double alphadelta = 0;
   char configfile[50];

   /*
	  Load rules
   */

   if (rules_loaded == 0) {
	  rules_loaded = 1;
          snprintf(configfile, sizeof(configfile), "%s/etc/password_strength.conf", VPOPMAILDIR);
	  if (!load_rules(configfile)) fprintf(stderr,"load_rules: failed\n");
   }

   if (password == NULL) return -69;

   /*
	  Count different character sets within password
   */

   n_lower = n_upper = n_numeric = n_other = n_alpha = 0;

   for (p = password; *p; p++) {
	  if ((*p >= 65) && (*p <= 90)) {
		 n_upper++;
		 n_alpha++;
	  }

	  else if ((*p >= 90) && (*p <= 122)) {
		 n_lower++;
		 n_alpha++;
	  }

	  else if ((*p >= '0') && (*p <= '9')) n_numeric++;
	  else n_other++;

	  len++;
   }

   /*
	  Test length
   */

   len = strlen(password);
   if (!(rule_is_true(&rule_length, len)))
	  return -70;

   /*
	  Calculate character set to length ratios
   */

   r_alpha = (double)(n_alpha / len);
   r_lower = (double)(n_lower / len);
   r_upper = (double)(n_upper / len);
   r_numeric = (double)(n_numeric / len);
   r_other = (double)(n_other / len);

#if 0
   printf("AR:%f LR:%f UR:%f NR:%f PR:%f\n",
		 r_alpha, r_lower, r_upper, r_numeric, r_other);
#endif

   alphadelta = (n_upper - n_lower);
   if (alphadelta < 0)
	  alphadelta = -(alphadelta);

   alphadelta /= n_alpha;

#if 0
   printf("LOWER:%f UPPER:%f DELTA: %f\n", n_lower, n_upper, alphadelta);
#endif

   /*
	  Test rules
   */

   if (!rule_is_true(&rule_alpha, r_alpha))         return -71;
   if (!rule_is_true(&rule_numeric, r_numeric))     return -72;
   if (!rule_is_true(&rule_other, r_other))         return -73;
   if (!rule_is_true(&rule_alphadelta, alphadelta)) return -74;

   return 1;
}

/*
   Based on the last test made, and the last error returned,
   generate an error string
*/

const char *pw_strength_error(void)
{
   static char b[512] = { 0 }, val[127] = { 0 };
   const char *condition = NULL, *name = NULL, *adjust = NULL;

   adjust = NULL;

   if (rule_last == NULL)
	  return "password suitable";

   switch(rule_last->test) {
	  case RULE_T_LESS:
	  case RULE_T_LESS_EQUAL:
		 condition = "should have less";
		 break;

	  case RULE_T_EQUAL:
		 condition = "can only be";
		 break;

	  case RULE_T_GREATER:
	  case RULE_T_GREATER_EQUAL:
		 condition = "requires more";
		 break;

	  default:
		 return "unknown password failure";
   };

   if (rule_last == &rule_alpha) name = "alphabetical characters";
   else if (rule_last == &rule_numeric) name = "numbers";

   else if (rule_last == &rule_alphadelta) {
	  name = "uppercase and lowercase character diversity";
	  if (condition == "should have less") condition = "requires more";
	  else condition = "should have less";
   }

   else if (rule_last == &rule_other) name = "punctuation, symbols, or other characters";

   else if (rule_last == &rule_length) {
	  if (condition == "can only be") {
		 condition = "must always be";
		 snprintf(val, sizeof(val), "%d characters long", (int)rule_last->value);
		 name = val;
	  }

	  else name = "characters";
   }

   else return "unknown password failure";

   snprintf(b, sizeof(b), "password %s %s %s", condition, name, adjust ? adjust : "");
   return (const char *)b;
}

/*
   Return configured policy string
*/

const char *pw_strength_policy(void)
{
   if (*rule_desc) return (const char *)rule_desc;

   return NULL;
}
