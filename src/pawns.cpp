/*
  Stockfish, a UCI chess playing engine derived from Glaurung 2.1
  Copyright (C) 2004-2022 The Stockfish developers (see AUTHORS file)

  Stockfish is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Stockfish is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <algorithm>
#include <cassert>

#include "bitboard.h"
#include "pawns.h"
#include "position.h"
#include "thread.h"

namespace Stockfish {

	namespace {

#define S(mg, eg) make_score(mg, eg)

		// Pawn penalties
		constexpr Score Backward = S(9, 22);
		constexpr Score Doubled = S(13, 51);
		constexpr Score DoubledEarly = S(20, 7);
		constexpr Score Isolated = S(3, 15);
		constexpr Score WeakLever = S(4, 58);
		constexpr Score WeakUnopposed = S(13, 24);

		// Bonus for blocked pawns at 5th or 6th rank
		constexpr Score BlockedPawn[2] = { S(-17, -6), S(-9, 2) };

		constexpr Score BlockedStorm[RANK_NB] = {
		  S(0, 0), S(0, 0), S(75, 78), S(-8, 16), S(-6, 10), S(-6, 6), S(0, 2)
		};

		// Connected pawn bonus
		constexpr int Connected[RANK_NB] = { 0, 5, 7, 11, 23, 48, 87 };

		// Strength of pawn shelter for our king by [distance from edge][rank].
		// RANK_1 = 0 is used for files where we have no pawn, or pawn is behind our king.
		constexpr Value ShelterStrength[static_cast<int>(FILE_NB) / 2][RANK_NB] = {
		  {static_cast<Value>(-5), static_cast<Value>(82), static_cast<Value>(92), static_cast<Value>(54), static_cast<Value>(36), static_cast<Value>(22), static_cast<Value>(28) },
		  {static_cast<Value>(-44), static_cast<Value>(63), static_cast<Value>(33), static_cast<Value>(-50), static_cast<Value>(-30), static_cast<Value>(-12), static_cast<Value>(-62) },
		  {static_cast<Value>(-11), static_cast<Value>(77), static_cast<Value>(22), static_cast<Value>(-6), static_cast<Value>(31), static_cast<Value>(8), static_cast<Value>(-45) },
		  {static_cast<Value>(-39), static_cast<Value>(-12), static_cast<Value>(-29), static_cast<Value>(-50), static_cast<Value>(-43), static_cast<Value>(-68), static_cast<Value>(-164) }
		};

		// Danger of enemy pawns moving toward our king by [distance from edge][rank].
		// RANK_1 = 0 is used for files where the enemy has no pawn, or their pawn
		// is behind our king. Note that UnblockedStorm[0][1-2] accommodate opponent pawn
		// on edge, likely blocked by our king.
		constexpr Value UnblockedStorm[static_cast<int>(FILE_NB) / 2][RANK_NB] = {
		  {static_cast<Value>(87), static_cast<Value>(-288), static_cast<Value>(-168), static_cast<Value>(96), static_cast<Value>(47), static_cast<Value>(44), static_cast<Value>(46) },
		  {static_cast<Value>(42), static_cast<Value>(-25), static_cast<Value>(120), static_cast<Value>(45), static_cast<Value>(34), static_cast<Value>(-9), static_cast<Value>(24) },
		  {static_cast<Value>(-8), static_cast<Value>(51), static_cast<Value>(167), static_cast<Value>(35), static_cast<Value>(-4), static_cast<Value>(-16), static_cast<Value>(-12) },
		  {static_cast<Value>(-17), static_cast<Value>(-13), static_cast<Value>(100), static_cast<Value>(4), static_cast<Value>(9), static_cast<Value>(-16), static_cast<Value>(-31) }
		};


		// KingOnFile[semi-open Us][semi-open Them] contains bonuses/penalties
		// for king when the king is on a semi-open or open file.
		constexpr Score KingOnFile[2][2] = { { S(-21,10), S(-7, 1)  },
										   {  S(0,-3), S(9,-4) } };

#undef S
#undef V


		/// evaluate() calculates a score for the static pawn structure of the given position.
		/// We cannot use the location of pieces or king in this function, as the evaluation
		/// of the pawn structure will be stored in a small cache for speed reasons, and will
		/// be re-used even when the pieces have moved.

		template<Color Us>
		Score evaluate(const Position& pos, Pawns::Entry* e) {

			constexpr Color     Them = ~Us;
			constexpr Direction Up = pawn_push(Us);
			constexpr Direction Down = -Up;

			Score score = SCORE_ZERO;
			Bitboard b = pos.pieces(Us, PAWN);

			Bitboard ourPawns = pos.pieces(Us, PAWN);
			Bitboard theirPawns = pos.pieces(Them, PAWN);

			const Bitboard doubleAttackThem = pawn_double_attacks_bb<Them>(theirPawns);

			e->passedPawns[Us] = 0;
			e->kingSquares[Us] = SQ_NONE;
			e->pawnAttacks[Us] = e->pawnAttacksSpan[Us] = pawn_attacks_bb<Us>(ourPawns);
			e->blockedCount += popcount(shift<Up>(ourPawns) & (theirPawns | doubleAttackThem));

			// Loop through all pawns of the current color and score each pawn
			while (b)
			{
				const Square s = pop_lsb(b);

				assert(pos.piece_on(s) == make_piece(Us, PAWN));

				const Rank r = relative_rank(Us, s);

				// Flag the pawn
				const Bitboard opposed = theirPawns & forward_file_bb(Us, s);
				const Bitboard blocked = theirPawns & (s + Up);
				const Bitboard stoppers = theirPawns & passed_pawn_span(Us, s);
				const Bitboard lever = theirPawns & pawn_attacks_bb(Us, s);
				const Bitboard leverPush = theirPawns & pawn_attacks_bb(Us, s + Up);
				const bool doubled = ourPawns & (s - Up);
				Bitboard neighbours = ourPawns & adjacent_files_bb(s);
				const Bitboard phalanx = neighbours & rank_bb(s);
				Bitboard support = neighbours & rank_bb(s - Up);

				if (doubled)
				{
					// Additional doubled penalty if none of their pawns is fixed
					if (!(ourPawns & shift<Down>(theirPawns | pawn_attacks_bb<Them>(theirPawns))))
						score -= DoubledEarly;
				}

				// A pawn is backward when it is behind all pawns of the same color on
				// the adjacent files and cannot safely advance.
				const bool backward = !(neighbours & forward_ranks_bb(Them, s + Up))
					&& (leverPush | blocked);

				// Compute additional span if pawn is not backward nor blocked
				if (!backward && !blocked)
					e->pawnAttacksSpan[Us] |= pawn_attack_span(Us, s);

				// A pawn is passed if one of the three following conditions is true:
				// (a) there is no stoppers except some levers
				// (b) the only stoppers are the leverPush, but we outnumber them
				// (c) there is only one front stopper which can be levered.
				//     (Refined in Evaluation::passed)
				bool passed = !(stoppers ^ lever)
					|| (!(stoppers ^ leverPush)
						&& popcount(phalanx) >= popcount(leverPush))
					|| (stoppers == blocked && r >= RANK_5
						&& (shift<Up>(support) & ~(theirPawns | doubleAttackThem)));

				passed &= !(forward_file_bb(Us, s) & ourPawns);

				// Passed pawns will be properly scored later in evaluation when we have
				// full attack info.
				if (passed)
					e->passedPawns[Us] |= s;

				// Score this pawn
				if (support | phalanx)
				{
					const int v = Connected[r] * (2 + static_cast<bool>(phalanx) - static_cast<bool>(opposed))
						+ 22 * popcount(support);

					score += make_score(v, v * (r - 2) / 4);
				}

				else if (!neighbours)
				{
					if (opposed
						&& (ourPawns & forward_file_bb(Them, s))
						&& !(theirPawns & adjacent_files_bb(s)))
						score -= Doubled;
					else
						score -= Isolated
						+ WeakUnopposed * !opposed;
				}

				else if (backward)
					score -= Backward
					+ WeakUnopposed * !opposed * static_cast<bool>(~(FileABB | FileHBB) & s);

				if (!support)
					score -= Doubled * doubled
					+ WeakLever * more_than_one(lever);

				if (blocked && r >= RANK_5)
					score += BlockedPawn[r - RANK_5];
			}

			return score;
		}

	} // namespace

	namespace Pawns {


		/// Pawns::probe() looks up the current position's pawns configuration in
		/// the pawns hash table. It returns a pointer to the Entry if the position
		/// is found. Otherwise a new Entry is computed and stored there, so we don't
		/// have to recompute all when the same pawns configuration occurs again.

		Entry* probe(const Position& pos) {
			const Key key = pos.pawn_key();
			Entry* e = pos.this_thread()->pawnsTable[key];

			if (e->key == key)
				return e;

			e->key = key;
			e->blockedCount = 0;
			e->scores[WHITE] = evaluate<WHITE>(pos, e);
			e->scores[BLACK] = evaluate<BLACK>(pos, e);

			return e;
		}


		/// Entry::evaluate_shelter() calculates the shelter bonus and the storm
		/// penalty for a king, looking at the king file and the two closest files.

		template<Color Us>
		Score Entry::evaluate_shelter(const Position& pos, const Square ksq) const {

			constexpr Color Them = ~Us;

			Bitboard b = pos.pieces(PAWN) & ~forward_ranks_bb(Them, ksq);
			Bitboard ourPawns = b & pos.pieces(Us) & ~pawnAttacks[Them];
			Bitboard theirPawns = b & pos.pieces(Them);

			Score bonus = make_score(5, 5);

			const File center = std::clamp(file_of(ksq), FILE_B, FILE_G);
			for (auto f = static_cast<File>(center - 1); f <= static_cast<File>(center + 1); ++f)
			{
				b = ourPawns & file_bb(f);
				const int ourRank = b ? relative_rank(Us, frontmost_sq(Them, b)) : 0;

				b = theirPawns & file_bb(f);
				const int theirRank = b ? relative_rank(Us, frontmost_sq(Them, b)) : 0;

				const int d = edge_distance(f);
				bonus += make_score(ShelterStrength[d][ourRank], 0);

				if (ourRank && (ourRank == theirRank - 1))
					bonus -= BlockedStorm[theirRank];
				else
					bonus -= make_score(UnblockedStorm[d][theirRank], 0);
			}

			// King On File
			bonus -= KingOnFile[pos.is_on_semiopen_file(Us, ksq)][pos.is_on_semiopen_file(Them, ksq)];

			return bonus;
		}


		/// Entry::do_king_safety() calculates a bonus for king safety. It is called only
		/// when king square changes, which is about 20% of total king_safety() calls.

		template<Color Us>
		Score Entry::do_king_safety(const Position& pos) {
			const Square ksq = pos.square<KING>(Us);
			kingSquares[Us] = ksq;
			castlingRights[Us] = pos.castling_rights(Us);
			auto compare = [](const Score a, const Score b) { return mg_value(a) < mg_value(b); };

			Score shelter = evaluate_shelter<Us>(pos, ksq);

			// If we can castle use the bonus after castling if it is bigger

			if (pos.can_castle(Us & KING_SIDE))
				shelter = std::max(shelter, evaluate_shelter<Us>(pos, relative_square(Us, SQ_G1)), compare);

			if (pos.can_castle(Us & QUEEN_SIDE))
				shelter = std::max(shelter, evaluate_shelter<Us>(pos, relative_square(Us, SQ_C1)), compare);

			// In endgame we like to bring our king near our closest pawn
			Bitboard pawns = pos.pieces(Us, PAWN);
			int minPawnDist = 6;

			if (pawns & attacks_bb<KING>(ksq))
				minPawnDist = 1;
			else while (pawns)
				minPawnDist = std::min(minPawnDist, distance(ksq, pop_lsb(pawns)));

			return shelter - make_score(0, 16 * minPawnDist);
		}

		// Explicit template instantiation
		template Score Entry::do_king_safety<WHITE>(const Position& pos);
		template Score Entry::do_king_safety<BLACK>(const Position& pos);

	} // namespace Pawns

} // namespace Stockfish
