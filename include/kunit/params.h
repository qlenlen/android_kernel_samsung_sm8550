/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Macros for parsing and manipulating parameter lists needed for generating
 * mocks.
 *
 * Copyright (C) 2020, Google LLC.
 * Author: Brendan Higgins <brendanhiggins@google.com>
 */

#ifndef _KUNIT_PARAMS_H
#define _KUNIT_PARAMS_H

#define NUM_VA_ARGS_IMPL(__dummy,					       \
			 __1,						       \
			 __2,						       \
			 __3,						       \
			 __4,						       \
			 __5,						       \
			 __6,						       \
			 __7,						       \
			 __8,						       \
			 __9,						       \
			 __10,						       \
			 __11,						       \
			 __12,						       \
			 __13,						       \
			 __14,						       \
			 __15,						       \
			 __16,						       \
			 __nargs, args...) __nargs

#define NUM_VA_ARGS(args...) NUM_VA_ARGS_IMPL(__dummy, ##args,		       \
					  16,				       \
					  15,				       \
					  14,				       \
					  13,				       \
					  12,				       \
					  11,				       \
					  10,				       \
					  9,				       \
					  8,				       \
					  7,				       \
					  6,				       \
					  5,				       \
					  4,				       \
					  3,				       \
					  2,				       \
					  1,				       \
					  0)

#define CONCAT_INTERNAL(left, right) left##right
#define CONCAT(left, right) CONCAT_INTERNAL(left, right)

#define EMPTY()

/*
 * Takes the name of a function style macro such as FOO() and prevents it from
 * being evaluated on the current pass.
 *
 * This is useful when you need to write a "recursive" macro since a macro name
 * becomes painted after it is pasted. If a different macro is pasted, this
 * different macro won't be pasted; if we then defer the evaluation of the this
 * "indirection macro", we can prevent the original definition from getting
 * painted.
 *
 * Example:
 *   #define EXAMPLE EXPAND(FOO()) // FOO() is evaluated on 1st pass.
 *   #define EXAMPLE EXPAND(DEFER(FOO)()) // FOO() is evaluated on the second
 *					  // pass.
 */
#define DEFER(macro_id) macro_id EMPTY()

/*
 * Takes the name of a function style macro such as FOO() and prevents it from
 * being evaluated on the current or following pass.
 *
 * This is useful when you need to DEFER inside an operation which causes an
 * extra pass, like IF.
 *
 * Example:
 *   #define EXAMPLE EXPAND(FOO()) // FOO() is evaluated on 1st pass.
 *   #define EXAMPLE EXPAND(DEFER(FOO)()) // FOO() is evaluated on the second
 *					  // pass.
 *   #define EXAMPLE EXPAND(OBSTRUCT(FOO)()) // FOO() is evaluated on the third
 *					     // pass.
 */
#define OBSTRUCT(macro_id) macro_id DEFER(EMPTY)()

#define EXPAND_1(args...) args
#define EXPAND_2(args...) EXPAND_1(EXPAND_1(args))
#define EXPAND_4(args...) EXPAND_2(EXPAND_2(args))
#define EXPAND_8(args...) EXPAND_4(EXPAND_4(args))
#define EXPAND_16(args...) EXPAND_8(EXPAND_8(args))

/*
 * Causes multiple evaluation passes of a macro.
 *
 * CPP is implemented as a push down automaton. It consumes a stream of tokens
 * and as it comes across macros, it either evaluates them and pastes the
 * result, or if the macro is a function macro, it pushes the macro to a stack,
 * it evaluates the input to the function macro, pops the state from the stack
 * and continues.
 *
 * This macro serves the function of making the cursor return to the beginging
 * of a macro that requires mulitple passes to evaluate. It is most useful when
 * used with DEFER(...) and OBSTRUCT(...).
 */
#define EXPAND(args...) EXPAND_16(args)

#define INC(id) INC_##id
#define INC_0  1
#define INC_1  2
#define INC_2  3
#define INC_3  4
#define INC_4  5
#define INC_5  6
#define INC_6  7
#define INC_7  8
#define INC_8  9
#define INC_9  10
#define INC_10 11
#define INC_11 12
#define INC_12 13
#define INC_13 14
#define INC_14 15
#define INC_15 16
#define INC_16 17

#define DEC(id) DEC_##id
#define DEC_1  0
#define DEC_2  1
#define DEC_3  2
#define DEC_4  3
#define DEC_5  4
#define DEC_6  5
#define DEC_7  6
#define DEC_8  7
#define DEC_9  8
#define DEC_10 9
#define DEC_11 10
#define DEC_12 11
#define DEC_13 12
#define DEC_14 13
#define DEC_15 14
#define DEC_16 15

#define DROP_FIRST_ARG_INTERNAL(dropped, x, args...) x
#define DROP_FIRST_ARG(args...) DROP_FIRST_ARG_INTERNAL(args)

#define EQUAL(left, right) EQUAL_##left##_##right
#define EQUAL_0_0 dropped, 1
#define EQUAL_1_1 dropped, 1
#define EQUAL_2_2 dropped, 1
#define EQUAL_3_3 dropped, 1
#define EQUAL_4_4 dropped, 1
#define EQUAL_5_5 dropped, 1
#define EQUAL_6_6 dropped, 1
#define EQUAL_7_7 dropped, 1
#define EQUAL_8_8 dropped, 1
#define EQUAL_9_9 dropped, 1
#define EQUAL_10_10 dropped, 1
#define EQUAL_11_11 dropped, 1
#define EQUAL_12_12 dropped, 1
#define EQUAL_13_13 dropped, 1
#define EQUAL_14_14 dropped, 1
#define EQUAL_15_15 dropped, 1
#define EQUAL_16_16 dropped, 1

#define IS_EQUAL(left, right) DROP_FIRST_ARG(EQUAL(left, right), 0)

#define NOT_INTERNAL(condition) NOT_##condition
#define NOT(condition) NOT_INTERNAL(condition)
#define NOT_0 1
#define NOT_1 0

#define IS_NOT_EQUAL(left, right) NOT(IS_EQUAL(left, right))

#define EMPTY_IMPL(tokens) CONCAT(EMPTY_, tokens)
#define IS_EMPTY(tokens)

#define OR_INTERNAL(left, right) OR_##left##_##right
#define OR(left, right) OR_INTERNAL(left, right)
#define OR_0_0 0
#define OR_0_1 1
#define OR_1_0 1
#define OR_1_1 1

#define IF(condition) CONCAT(IF_, condition)
#define IF_0(body)
#define IF_1(body) body

#define COMMA() ,

#define APPLY_TOKENS_INTERNAL(tokens, yield_token, seen_token) \
		IF(yield_token)(IF(seen_token)(COMMA()) tokens)
#define APPLY_TOKENS(tokens, yield_token, seen_token) \
		APPLY_TOKENS_INTERNAL(tokens, yield_token, seen_token)

/*
 * Provides the indirection to keep the PARAM_LIST_RECURSE_INTERNAL from getting
 * pasted, only useful if used with DEFER(...) or OBSTRUCT(...).
 */
#define PARAM_LIST_RECURSE_INDIRECT() PARAM_LIST_RECURSE_INTERNAL

/*
 * Given a starting index, a number of args, a MACRO to apply, and a list of
 * types (with at least one element) this will call MACRO with the first type in
 * the list and index; it will then call itself again on all remaining types, if
 * any, while incrementing index, and decrementing nargs.
 *
 * Assumes nargs is the number of types in the list.
 */
#define PARAM_LIST_RECURSE_INTERNAL(index,				       \
				    nargs,				       \
				    MACRO,				       \
				    FILTER,				       \
				    context,				       \
				    seen_token,				       \
				    type,				       \
				    args...)				       \
		APPLY_TOKENS(MACRO(context, type, index),		       \
			     FILTER(context, type, index),		       \
			     seen_token)				       \
		IF(IS_NOT_EQUAL(nargs, 1))				       \
			(OBSTRUCT(PARAM_LIST_RECURSE_INDIRECT)()	       \
			 (INC(index), DEC(nargs),			       \
			  MACRO, FILTER, context,			       \
			  OR(seen_token, FILTER(context, type, index)),	       \
			  args))

#define PARAM_LIST_RECURSE(index, nargs, MACRO, FILTER, context, args...)      \
		IF(IS_NOT_EQUAL(nargs, 0))				       \
			(OBSTRUCT(PARAM_LIST_RECURSE_INTERNAL)(index,	       \
							       nargs,	       \
							       MACRO,	       \
							       FILTER,	       \
							       context,	       \
							       0,	       \
							       args))

#define FILTER_NONE(context, type, index) 1

#define FILTER_INDEX_INTERNAL(index_to_drop, type, index) \
		IS_NOT_EQUAL(index, index_to_drop)
#define FILTER_INDEX(index_to_drop, type, index) \
		FILTER_INDEX_INTERNAL(index_to_drop, type, index)

/*
 * Applies a MACRO which takes a type and the index of the type and outputs a
 * sequence of tokens to a list of types.
 */
#define FOR_EACH_PARAM(MACRO, FILTER, context, args...) \
		EXPAND(PARAM_LIST_RECURSE(0,\
					  NUM_VA_ARGS(args),\
					  MACRO,\
					  FILTER,\
					  context,\
					  args))

#define PRODUCE_TYPE_AND_ARG(context, type, index) type arg##index
#define PARAM_LIST_FROM_TYPES(args...)					       \
		FOR_EACH_PARAM(PRODUCE_TYPE_AND_ARG,			       \
			       FILTER_NONE,				       \
			       not_used,				       \
			       args)

#define PRODUCE_TYPE_NAME(context, type, index) #type
#define TYPE_NAMES_FROM_TYPES(handle_index, args...)			       \
		FOR_EACH_PARAM(PRODUCE_TYPE_NAME,			       \
			       FILTER_INDEX,				       \
			       handle_index,				       \
			       args)

#define PRODUCE_PTR_TO_ARG(context, type, index) &arg##index
#define PTR_TO_ARG_FROM_TYPES(handle_index, args...)			       \
		FOR_EACH_PARAM(PRODUCE_PTR_TO_ARG,			       \
			       FILTER_INDEX,				       \
			       handle_index,				       \
			       args)

#define PRODUCE_MATCHER_AND_ARG(ctrl_index, type, index)		       \
		IF(IS_EQUAL(index, ctrl_index))(struct mock *arg##ctrl_index)  \
		IF(IS_NOT_EQUAL(index, ctrl_index))(			       \
				struct mock_param_matcher *arg##index)
#define MATCHER_PARAM_LIST_FROM_TYPES(ctrl_index, args...)		       \
		FOR_EACH_PARAM(PRODUCE_MATCHER_AND_ARG,			       \
			       FILTER_NONE,				       \
			       ctrl_index,				       \
			       args)

#define PRODUCE_ARG(context, type, index) arg##index
#define ARG_NAMES_FROM_TYPES(ctrl_index, args...)			       \
		FOR_EACH_PARAM(PRODUCE_ARG,				       \
			       FILTER_INDEX,				       \
			       ctrl_index,				       \
			       args)

#define PRODUCE_ARRAY_ACCESSOR(context, type, index) *((type *) params[index])
#define ARRAY_ACCESSORS_FROM_TYPES(args...)				       \
		FOR_EACH_PARAM(PRODUCE_ARRAY_ACCESSOR,			       \
			       FILTER_NONE,				       \
			       not_used,				       \
			       args)

#endif /* _KUNIT_PARAMS_H */
