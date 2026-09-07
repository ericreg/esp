//! Local administration protocol and terminal UI. All writes go through the transport actor.
use super::*;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io::IsTerminal;

const PAGE_SIZE: usize = 50;
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(super) enum Request {
    #[n(0)]
    Overview,
    #[n(1)]
    Peers {
        #[n(0)]
        revision: String,
        #[n(1)]
        offset: usize,
    },
    #[n(2)]
    Detail {
        #[n(0)]
        #[cbor(with = "cbor::endpoint_id")]
        node_id: EndpointId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub(super) enum Response {
    #[n(0)]
    Overview(#[n(0)] Overview),
    #[n(1)]
    Peers {
        #[n(0)]
        revision: String,
        #[n(1)]
        peers: Vec<PeerRow>,
    },
    #[n(2)]
    Detail(#[n(0)] PeerDetail),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub(super) struct Overview {
    #[n(0)]
    pub(super) network_id: String,
    #[n(1)]
    pub(super) local_name: String,
    #[n(2)]
    pub(super) revision: String,
    #[n(3)]
    pub(super) total: usize,
    #[n(4)]
    pub(super) connected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub(super) struct PeerRow {
    #[n(0)]
    #[cbor(with = "cbor::endpoint_id")]
    pub(super) node_id: EndpointId,
    #[n(1)]
    pub(super) admin_label: String,
    #[n(2)]
    pub(super) hostname: String,
    #[n(3)]
    pub(super) connection_id: String,
    #[n(4)]
    pub(super) active_connections: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(array)]
pub(super) struct PeerDetail {
    #[n(0)]
    pub(super) peer: PeerRow,
    #[n(1)]
    pub(super) role: MembershipRole,
    #[n(2)]
    pub(super) allowed_ports: Vec<u16>,
    #[n(3)]
    pub(super) invite_id: Option<String>,
    #[n(4)]
    #[cbor(with = "cbor::endpoint_id")]
    pub(super) inviter: EndpointId,
    #[n(5)]
    pub(super) joined_at: u64,
    #[n(6)]
    pub(super) last_connected: Option<u64>,
}

type Presence = HashMap<EndpointId, HashSet<Uuid>>;

fn rows(cfg: &Config, presence: &Presence) -> Vec<PeerRow> {
    let mut rows: Vec<_> = cfg
        .peers
        .iter()
        .filter(|peer| !is_node_revoked(cfg, peer.node_id))
        .filter_map(|peer| {
            let member = find_membership_by_subject(cfg, &[], peer.node_id)?;
            Some(PeerRow {
                node_id: peer.node_id,
                admin_label: member.admin_label.clone(),
                hostname: peer.name.clone(),
                connection_id: peer.connection_id.clone(),
                active_connections: presence.get(&peer.node_id).map_or(0, HashSet::len),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        a.admin_label
            .cmp(&b.admin_label)
            .then(a.connection_id.cmp(&b.connection_id))
    });
    rows
}

fn overview(cfg: &Config, rows: &[PeerRow]) -> Result<Overview> {
    // Connection events and timestamps do not invalidate directory pagination.
    let mut hash = Sha256::new();
    hash.update(cfg.network_id.as_bytes());
    hash.update(minicbor::to_vec(&cfg.peers)?);
    hash.update(minicbor::to_vec(&cfg.memberships)?);
    Ok(Overview {
        network_id: cfg.network_id.clone(),
        local_name: cfg.name.clone(),
        revision: URL_SAFE_NO_PAD.encode(hash.finalize()),
        total: rows.len(),
        connected: rows.iter().filter(|row| row.active_connections > 0).count(),
    })
}

fn detail(cfg: &Config, peer: PeerRow) -> Result<PeerDetail> {
    let member = find_membership_by_subject(cfg, &[], peer.node_id)
        .ok_or_else(|| anyhow!("peer membership is unavailable"))?;
    Ok(PeerDetail {
        role: member.role,
        allowed_ports: member.allowed_ports()?,
        invite_id: member.invite_id.clone(),
        inviter: member.issuer_node_id,
        joined_at: member.joined_at_unix,
        last_connected: cfg
            .peer_last_connected
            .get(&peer.node_id.to_string())
            .copied(),
        peer,
    })
}

pub(super) fn respond(cfg: &Config, presence: &Presence, request: Request) -> Result<Response> {
    cfg.ensure_local_admin()?;
    let peers = rows(cfg, presence);
    match request {
        Request::Overview => Ok(Response::Overview(overview(cfg, &peers)?)),
        Request::Peers { revision, offset } => {
            let current = overview(cfg, &peers)?;
            if revision != current.revision {
                bail!("peer directory changed; refreshing again");
            }
            if offset > peers.len() {
                bail!("invalid peer page offset");
            }
            Ok(Response::Peers {
                revision,
                peers: peers.into_iter().skip(offset).take(PAGE_SIZE).collect(),
            })
        }
        Request::Detail { node_id } => {
            let peer = peers
                .into_iter()
                .find(|peer| peer.node_id == node_id)
                .ok_or_else(|| anyhow!("peer is no longer in this network"))?;
            Ok(Response::Detail(detail(cfg, peer)?))
        }
    }
}

#[derive(Clone)]
pub(super) struct View {
    pub(super) overview: Overview,
    pub(super) peers: Vec<PeerRow>,
    pub(super) online: bool,
}

fn offline_view() -> Result<View> {
    let cfg = Config::load(&config_path()?)?;
    cfg.ensure_local_admin()?;
    let peers = rows(&cfg, &Presence::new());
    Ok(View {
        overview: overview(&cfg, &peers)?,
        peers,
        online: false,
    })
}

async fn request(request: Request) -> Result<Option<Response>> {
    match timeout(
        FETCH_TIMEOUT,
        send_local_control_request(LocalControlRequest::Admin { request }),
    )
    .await
    .context("local transport is not responding; data is stale")??
    {
        Some(LocalControlOk::Admin { report }) => Ok(Some(report)),
        None => Ok(None),
        _ => bail!("incompatible local transport; restart it with the upgraded esp binary"),
    }
}

async fn fetch_view() -> Result<View> {
    let overview = match request(Request::Overview).await? {
        Some(Response::Overview(overview)) => overview,
        None => return offline_view(),
        _ => bail!("invalid admin overview response"),
    };
    if overview.total > ABSOLUTE_MAX_KNOWN_PEERS {
        bail!("invalid admin peer count");
    }
    let mut peers = Vec::with_capacity(overview.total);
    while peers.len() < overview.total {
        let Some(Response::Peers {
            revision,
            peers: page,
        }) = request(Request::Peers {
            revision: overview.revision.clone(),
            offset: peers.len(),
        })
        .await?
        else {
            bail!("local transport stopped; data is stale");
        };
        if revision != overview.revision || page.is_empty() || page.len() > PAGE_SIZE {
            bail!("peer directory changed; refreshing again");
        }
        if peers.len() + page.len() > overview.total {
            bail!("invalid admin peer page");
        }
        peers.extend(page);
    }
    Ok(View {
        overview,
        peers,
        online: true,
    })
}

async fn fetch_detail(node_id: EndpointId, online: bool) -> Result<PeerDetail> {
    if online {
        match request(Request::Detail { node_id }).await? {
            Some(Response::Detail(detail)) if detail.peer.node_id == node_id => Ok(detail),
            _ => bail!("peer details are unavailable; refreshing again"),
        }
    } else {
        let cfg = Config::load(&config_path()?)?;
        match respond(&cfg, &Presence::new(), Request::Detail { node_id })? {
            Response::Detail(detail) => Ok(detail),
            _ => unreachable!(),
        }
    }
}

pub(super) struct App {
    pub(super) view: View,
    pub(super) list: ListState,
    pub(super) detail: Option<PeerDetail>,
    pub(super) scroll: u16,
    pub(super) confirmation: Option<PeerRow>,
    pub(super) confirm_yes: bool,
    pub(super) revoking: bool,
    pub(super) message: String,
}

pub(super) enum Action {
    None,
    Quit,
    Detail,
    Revoke(EndpointId),
}

impl App {
    pub(super) fn new(view: View) -> Self {
        let mut list = ListState::default();
        if !view.peers.is_empty() {
            list.select(Some(0));
        }
        Self {
            view,
            list,
            detail: None,
            scroll: 0,
            confirmation: None,
            confirm_yes: false,
            revoking: false,
            message: String::new(),
        }
    }
    pub(super) fn selected(&self) -> Option<&PeerRow> {
        self.list
            .selected()
            .and_then(|index| self.view.peers.get(index))
    }
    pub(super) fn update(&mut self, view: View) {
        let selected = self.selected().map(|peer| peer.node_id);
        let network_changed = self.view.overview.network_id != view.overview.network_id;
        let index = view
            .peers
            .iter()
            .position(|peer| Some(peer.node_id) == selected)
            .unwrap_or(
                self.list
                    .selected()
                    .unwrap_or(0)
                    .min(view.peers.len().saturating_sub(1)),
            );
        self.list.select(if view.peers.is_empty() {
            None
        } else {
            Some(index)
        });
        if network_changed
            || !view.online
            || self
                .confirmation
                .as_ref()
                .is_some_and(|peer| !view.peers.iter().any(|row| row.node_id == peer.node_id))
        {
            self.confirmation = None;
        }
        if !self.view.online && view.online {
            self.message.clear();
        }
        self.view = view;
        if network_changed || self.selected().map(|peer| peer.node_id) != selected {
            self.detail = None;
            self.scroll = 0;
        }
    }
    pub(super) fn key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if let Some(peer) = self.confirmation.clone() {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.confirmation = None,
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    self.confirm_yes = !self.confirm_yes
                }
                KeyCode::Enter => {
                    self.confirmation = None;
                    if self.confirm_yes && self.view.online && !self.revoking {
                        self.revoking = true;
                        self.message = format!("Revoking {}...", peer.admin_label);
                        return Action::Revoke(peer.node_id);
                    }
                }
                _ => {}
            }
            return Action::None;
        }
        let delta = match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Char('r') if !self.revoking => {
                if !self.view.online {
                    self.message = "Revocation disabled: start esp daemon to manage peers.".into();
                } else {
                    self.confirmation = self.selected().cloned();
                    self.confirm_yes = false;
                }
                return Action::None;
            }
            KeyCode::Down | KeyCode::Char('j') => 1,
            KeyCode::Up | KeyCode::Char('k') => -1,
            KeyCode::PageDown => 10,
            KeyCode::PageUp => -10,
            KeyCode::Char('J') => {
                self.scroll = self.scroll.saturating_add(1);
                return Action::None;
            }
            KeyCode::Char('K') => {
                self.scroll = self.scroll.saturating_sub(1);
                return Action::None;
            }
            _ => return Action::None,
        };
        if !self.view.peers.is_empty() {
            let index = (self.list.selected().unwrap_or(0) as isize + delta)
                .clamp(0, self.view.peers.len() as isize - 1) as usize;
            self.list.select(Some(index));
            self.detail = None;
            self.scroll = 0;
            return Action::Detail;
        }
        Action::None
    }
    pub(super) fn stale(&mut self, message: String) {
        self.view.online = false;
        self.confirmation = None;
        self.message = message;
    }
    pub(super) fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < 80 || area.height < 20 {
            frame.render_widget(
                Paragraph::new("Resize terminal to at least 80 x 20. q: quit"),
                area,
            );
            return;
        }
        let sections = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
        let counts = if self.view.online {
            format!(
                "{} connected / {} peers",
                self.view.overview.connected,
                self.view.peers.len()
            )
        } else {
            format!(
                "{} peers | connection status Unknown",
                self.view.peers.len()
            )
        };
        let header = format!(
            "Network {}\nLocal host: {} | {} | {}",
            self.view.overview.network_id,
            self.view.overview.local_name,
            if self.view.online {
                "Transport running"
            } else {
                "Offline / stale - view only"
            },
            counts
        );
        frame.render_widget(
            Paragraph::new(header).block(Block::bordered().title(" esp admin ")),
            sections[0],
        );
        let panes = Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(sections[1]);
        let items: Vec<_> = self
            .view
            .peers
            .iter()
            .map(|peer| {
                let connected = self.view.online && peer.active_connections > 0;
                let status = if !self.view.online {
                    "Unknown"
                } else if connected {
                    "Connected"
                } else {
                    "Disconnected"
                };
                ListItem::new(vec![
                    Line::from(Span::styled(
                        peer.admin_label.clone(),
                        Style::default()
                            .fg(if connected { Color::Green } else { Color::Gray })
                            .add_modifier(Modifier::BOLD),
                    )),
                    Line::from(format!("{} ({})", peer.hostname, peer.connection_id)),
                    Line::from(Span::styled(
                        status,
                        Style::default().fg(if connected { Color::Green } else { Color::Gray }),
                    )),
                ])
            })
            .collect();
        if items.is_empty() {
            frame.render_widget(
                Paragraph::new(
                    "No joined peers.\n\nCreate a named invite with:\nesp invite \"name\"",
                )
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(" Peers ")),
                panes[0],
            );
        } else {
            frame.render_stateful_widget(
                List::new(items)
                    .block(Block::bordered().title(" Peers "))
                    .highlight_symbol("> ")
                    .highlight_style(
                        Style::default()
                            .bg(Color::DarkGray)
                            .add_modifier(Modifier::BOLD),
                    ),
                panes[0],
                &mut self.list,
            );
        }
        let text = match self.selected() {
            None => vec![Line::from("Select a peer to view its details.")],
            Some(peer) => {
                let status = if !self.view.online {
                    "Unknown"
                } else if peer.active_connections > 0 {
                    "Connected"
                } else {
                    "Disconnected"
                };
                let mut status_value = Span::raw(status);
                if self.view.online && peer.active_connections > 0 {
                    status_value = status_value.style(
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    );
                }
                let mut text = vec![
                    detail_line("Admin label", peer.admin_label.clone()),
                    detail_line("Hostname", peer.hostname.clone()),
                    detail_line("Connection ID", peer.connection_id.clone()),
                    detail_line("Node ID", peer.node_id.to_string()),
                    detail_line("Status", status_value),
                ];
                if let Some(detail) = self
                    .detail
                    .as_ref()
                    .filter(|detail| detail.peer.node_id == peer.node_id)
                {
                    text.extend([
                        detail_line("Role", detail.role.to_string()),
                        detail_line("Allowed ports", format_ports(&detail.allowed_ports)),
                        detail_line(
                            "Invite ID",
                            detail.invite_id.clone().unwrap_or_else(|| {
                                if detail.inviter == peer.node_id {
                                    "None (network creator)".into()
                                } else {
                                    "Not recorded".into()
                                }
                            }),
                        ),
                        detail_line("Inviter", detail.inviter.to_string()),
                        detail_line("Joined", timestamp(Some(detail.joined_at))),
                        detail_line(
                            "Active connections",
                            if self.view.online {
                                peer.active_connections.to_string()
                            } else {
                                "Unknown".into()
                            },
                        ),
                        detail_line("Last connected", timestamp(detail.last_connected)),
                        Line::default(),
                        Line::from("Connection status and history are observed by this host."),
                    ]);
                } else {
                    text.extend([Line::default(), Line::from("Loading details...")]);
                }
                text
            }
        };
        let paragraph = Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Peer details "));
        self.scroll = self.scroll.min(
            paragraph
                .line_count(panes[1].width.saturating_sub(2))
                .saturating_sub(panes[1].height.saturating_sub(2) as usize)
                .min(u16::MAX as usize) as u16,
        );
        frame.render_widget(paragraph.scroll((self.scroll, 0)), panes[1]);
        frame.render_widget(
            Paragraph::new(format!(
                "j/k or arrows: select | PgUp/PgDn: page | J/K: details | r: revoke | q: quit\n{}",
                self.message
            ))
            .wrap(Wrap { trim: false }),
            sections[2],
        );
        if let Some(peer) = &self.confirmation {
            let width = area.width.min(76);
            let height = 14;
            let dialog = Rect::new(
                (area.width - width) / 2,
                (area.height - height) / 2,
                width,
                height,
            );
            frame.render_widget(Clear, dialog);
            let buttons = if self.confirm_yes {
                "  Cancel     [ Revoke ]"
            } else {
                "[ Cancel ]     Revoke"
            };
            frame.render_widget(Paragraph::new(format!("Revoke {}?\nHost: {} ({})\nNode: {}\n\nActive connections will close. This peer must rejoin with a new invite.\n{}\nTab/arrows: choose | Enter: confirm | Esc: cancel", peer.admin_label, peer.hostname, peer.connection_id, peer.node_id, buttons))
                .wrap(Wrap { trim: false }).block(Block::bordered().title(" Confirm revocation ")), dialog);
        }
    }
}

fn detail_line(label: &str, value: impl Into<Span<'static>>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label}:"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        value.into(),
    ])
}

pub(super) fn timestamp(value: Option<u64>) -> String {
    let Some(value) = value else {
        return "Never observed".into();
    };
    let absolute = i64::try_from(value)
        .ok()
        .and_then(|value| ::time::OffsetDateTime::from_unix_timestamp(value).ok())
        .and_then(|value| {
            value
                .format(&::time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "Unknown".into());
    let now = current_unix_time().unwrap_or(value);
    let age = now.saturating_sub(value);
    let relative = if value > now {
        "clock is ahead".into()
    } else if age < 60 {
        format!("{age}s ago")
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86400)
    };
    format!("{absolute} ({relative})")
}

struct RestoreTerminal;
impl Drop for RestoreTerminal {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

enum Update {
    View(Result<View>),
    Detail(EndpointId, Result<PeerDetail>),
    Revoked(Result<RevocationReport>),
}

pub(super) async fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("esp admin requires an interactive terminal (use ssh -t for remote access)");
    }
    let mut app = App::new(offline_view()?);
    let mut terminal = ratatui::init();
    let _restore = RestoreTerminal;
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut jobs = tokio::task::JoinSet::new();
    let mut refreshing = false;
    let mut detail_job: Option<tokio::task::AbortHandle> = None;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        terminal.draw(|frame| app.render(frame))?;
        let mut refresh_detail = false;
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                if !refreshing && !app.revoking {
                    refreshing = true;
                    jobs.spawn(async { Update::View(fetch_view().await) });
                }
            }
            event = events.next() => {
                match event {
                    Some(Ok(Event::Key(key))) => match app.key(key) {
                        Action::Quit => break,
                        Action::Detail => refresh_detail = true,
                        Action::Revoke(node_id) => {
                            // Discard reads that could otherwise resurrect a revoked row.
                            jobs.abort_all();
                            refreshing = false;
                            // Never use the file-writing CLI fallback from the TUI.
                            jobs.spawn(async move { Update::Revoked(async {
                                request_daemon_revoke(&node_id.to_string()).await?
                                    .ok_or_else(|| anyhow!("local transport stopped; revocation was not applied"))
                            }.await) });
                        }
                        Action::None => {}
                    },
                    Some(Ok(_)) => {},
                    Some(Err(err)) => return Err(err.into()),
                    None => break,
                }
            }
            update = jobs.join_next(), if !jobs.is_empty() => {
                match update {
                    Some(Ok(Update::View(result))) => {
                        refreshing = false;
                        match result {
                            Ok(view) => { app.update(view); refresh_detail = true; }
                            Err(err) => app.stale(format!("{err:#}")),
                        }
                    }
                    Some(Ok(Update::Detail(node_id, result))) => {
                        if app.selected().is_some_and(|peer| peer.node_id == node_id) {
                            match result {
                                Ok(detail) => app.detail = Some(detail),
                                Err(err) => app.message = format!("{err:#}"),
                            }
                        }
                    }
                    Some(Ok(Update::Revoked(result))) => {
                        app.revoking = false;
                        match result {
                            Ok(report) => {
                                let mut view = app.view.clone();
                                view.peers.retain(|peer| peer.node_id != report.node_id);
                                view.overview.total = view.peers.len();
                                view.overview.connected = view.peers.iter().filter(|peer| peer.active_connections > 0).count();
                                app.update(view);
                                app.message = format!("Revoked {}", report.display_name);
                                refresh_detail = true;
                            }
                            Err(err) => app.stale(format!("Revocation failed: {err:#}")),
                        }
                        tick.reset_immediately();
                    }
                    Some(Err(err)) if err.is_cancelled() => {},
                    Some(Err(err)) => return Err(err.into()),
                    None => {},
                }
            }
        }
        if refresh_detail {
            if let Some(job) = detail_job.take() {
                job.abort();
            }
            if let Some(peer) = app.selected() {
                let node_id = peer.node_id;
                let online = app.view.online;
                detail_job = Some(jobs.spawn(async move {
                    Update::Detail(node_id, fetch_detail(node_id, online).await)
                }));
            }
        }
    }
    // Aborting view requests is safe; confirmed revocations are processed by the actor.
    jobs.abort_all();
    Ok(())
}
