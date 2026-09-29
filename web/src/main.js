import { ready } from '../../shared/crypto.js';
import { route, render } from './ui.js';
import { HomePage, SafetyPage, ProtectedPage, TermsPage, RightsPage, VerifyPage } from './pages.js';
import { StartPage, EnrollPage, JoinPage, MemberPage, DisavowPage } from './organize.js';
import { TrusteeDashboard, UnlockPage } from './trustee.js';
import { ClaimPage, WsEntry, UnionTab } from './workspace.js';
import { guarded } from './wsbase.js';
import { VotesTab, VoteDetail, TallyPage } from './ws-votes.js';
import { HelpTab, CaseDetail } from './ws-help.js';
import { MoneyTab } from './ws-money.js';

await ready; // libsodium's WebAssembly must be loaded before anything touches a key

route('/', HomePage);
route('/start', StartPage);
route('/protected', ProtectedPage);
route('/rights', RightsPage);
route('/safety', SafetyPage);
route('/terms', TermsPage);
route('/verify', VerifyPage);
route('/t', EnrollPage);
route('/t/dashboard', TrusteeDashboard);
route('/t/unlock', UnlockPage);
route('/j', JoinPage);
route('/m', MemberPage);
route('/d', DisavowPage);
route('/w/join', ClaimPage);
route('/w', WsEntry);
route('/w/votes', guarded(VotesTab));
route('/w/votes/:id', guarded(VoteDetail));
route('/w/votes/:id/tally', guarded(TallyPage));
route('/w/help', guarded(HelpTab));
route('/w/help/:id', guarded(CaseDetail));
route('/w/money', guarded(MoneyTab));
route('/w/union', guarded(UnionTab));

render();
