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
    #[n(5)]
    pub(super) network_label: Option<String>,
    #[n(6)]
    pub(super) local_role: Option<MembershipRole>,
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
        local_role: cfg.local_membership_role(),
        network_label: cfg.network_policy.admin_label.clone(),
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
    cfg.ensure_active()?;
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

fn offline_view(id: &str) -> Result<View> {
    let cfg = networks::Store::local()?.load(id)?;
    cfg.ensure_active()?;
    let peers = rows(&cfg, &Presence::new());
    Ok(View {
        overview: overview(&cfg, &peers)?,
        peers,
        online: false,
    })
}

async fn request(id: &str, request: Request) -> Result<Option<Response>> {
    match timeout(
        FETCH_TIMEOUT,
        networks::send(&networks::Request::Network {
            id: id.into(),
            request: LocalControlRequest::Admin { request },
        }),
    )
    .await
    .context("local transport is not responding; data is stale")??
    {
        Some(response) => match response.network()? {
            LocalControlOk::Admin { report } => Ok(Some(report)),
            _ => bail!("unexpected admin response"),
        },
        None => Ok(None),
    }
}

async fn fetch_view(id: &str) -> Result<View> {
    let overview = match request(id, Request::Overview).await? {
        Some(Response::Overview(overview)) => overview,
        None => return offline_view(id),
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
        }) = request(
            id,
            Request::Peers {
                revision: overview.revision.clone(),
                offset: peers.len(),
            },
        )
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

async fn fetch_detail(id: &str, node_id: EndpointId, online: bool) -> Result<PeerDetail> {
    if online {
        match request(id, Request::Detail { node_id }).await? {
            Some(Response::Detail(detail)) if detail.peer.node_id == node_id => Ok(detail),
            _ => bail!("peer details are unavailable; refreshing again"),
        }
    } else {
        let cfg = networks::Store::local()?.load(id)?;
        match respond(&cfg, &Presence::new(), Request::Detail { node_id })? {
            Response::Detail(detail) => Ok(detail),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone)]
pub(super) struct NetworkRow {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) role: String,
}
fn empty_view(id: String, label: String) -> View {
    View {
        overview: Overview {
            network_id: id,
            network_label: Some(label),
            local_name: String::new(),
            revision: String::new(),
            total: 0,
            connected: 0,
            local_role: None,
        },
        peers: Vec::new(),
        online: false,
    }
}
async fn fetch_networks() -> Result<Vec<NetworkRow>> {
    let value = match networks::send(&networks::Request::Status {
        id: None,
        peers: false,
    })
    .await?
    {
        Some(response) => response.json()?,
        None => networks::offline_status(&networks::Store::local()?, None, false)?,
    };
    Ok(value["networks"]
        .as_array()
        .ok_or_else(|| anyhow!("invalid network list"))?
        .iter()
        .map(|n| NetworkRow {
            id: n["network_id"].as_str().unwrap_or_default().into(),
            label: n["network_label"].as_str().unwrap_or_default().into(),
            role: n["role"].as_str().unwrap_or("unavailable").into(),
        })
        .collect())
}

pub(super) struct App {
    pub(super) networks: Vec<NetworkRow>,
    pub(super) network_list: ListState,
    pub(super) focus: usize,
    pub(super) generation: u64,
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
    Network,
    Revoke(EndpointId),
}

impl App {
    pub(super) fn new(view: View) -> Self {
        let mut list = ListState::default();
        if !view.peers.is_empty() {
            list.select(Some(0));
        }
        Self {
            networks: vec![NetworkRow {
                id: view.overview.network_id.clone(),
                label: view.overview.network_label.clone().unwrap_or_default(),
                role: view
                    .overview
                    .local_role
                    .map_or("unknown".into(), |r| r.to_string()),
            }],
            network_list: ListState::default().with_selected(Some(0)),
            focus: 1,
            generation: 0,
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
    pub(super) fn set_networks(&mut self, networks: Vec<NetworkRow>) -> bool {
        let id = self.view.overview.network_id.clone();
        let index = networks.iter().position(|n| n.id == id).unwrap_or(0);
        self.networks = networks;
        self.network_list
            .select((!self.networks.is_empty()).then_some(index));
        let selected_id = self
            .networks
            .get(index)
            .map(|n| n.id.as_str())
            .unwrap_or("");
        if selected_id != id {
            self.select_network();
            return true;
        }
        false
    }
    fn select_network(&mut self) {
        let selected = self
            .network_list
            .selected()
            .and_then(|i| self.networks.get(i));
        self.update(empty_view(
            selected.map(|n| n.id.clone()).unwrap_or_default(),
            selected.map(|n| n.label.clone()).unwrap_or_default(),
        ));
        self.generation += 1;
        self.detail = None;
        self.confirmation = None;
        self.revoking = false;
        self.message.clear();
    }
    fn can_revoke(&self) -> bool {
        self.view.online && self.view.overview.local_role == Some(MembershipRole::Admin)
    }
    pub(super) fn accept_detail(&mut self, id: &str, generation: u64, detail: PeerDetail) -> bool {
        if id == self.view.overview.network_id
            && generation == self.generation
            && self
                .selected()
                .is_some_and(|peer| peer.node_id == detail.peer.node_id)
        {
            self.detail = Some(detail);
            true
        } else {
            false
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
                KeyCode::Esc | KeyCode::Char('q' | 'n' | 'N') => self.confirmation = None,
                KeyCode::Left | KeyCode::Right | KeyCode::Tab => {
                    self.confirm_yes = !self.confirm_yes
                }
                KeyCode::Enter | KeyCode::Char('y' | 'Y') => {
                    self.confirmation = None;
                    if (self.confirm_yes || matches!(key.code, KeyCode::Char('y' | 'Y')))
                        && self.can_revoke()
                        && !self.revoking
                    {
                        self.revoking = true;
                        self.message = format!("Revoking {}...", peer.admin_label);
                        return Action::Revoke(peer.node_id);
                    }
                }
                _ => {}
            }
            return Action::None;
        }
        match key.code {
            KeyCode::Tab => {
                self.focus = (self.focus + 1) % 3;
                return Action::None;
            }
            KeyCode::BackTab => {
                self.focus = (self.focus + 2) % 3;
                return Action::None;
            }
            _ => {}
        }
        if self.revoking && key.code != KeyCode::Char('q') {
            return Action::None;
        }
        let delta = match key.code {
            KeyCode::Char('q') => return Action::Quit,
            KeyCode::Char('r') if !self.revoking => {
                if !self.can_revoke() {
                    self.message = "Revocation disabled: requires an online administrator.".into();
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
        if self.focus == 0 {
            if !self.networks.is_empty() {
                let index = (self.network_list.selected().unwrap_or(0) as isize + delta)
                    .clamp(0, self.networks.len() as isize - 1)
                    as usize;
                if self.network_list.selected() != Some(index) {
                    self.network_list.select(Some(index));
                    self.select_network();
                    return Action::Network;
                }
            }
            return Action::None;
        }
        if self.focus == 2 {
            self.scroll = (self.scroll as isize + delta).clamp(0, u16::MAX as isize) as u16;
            return Action::None;
        }
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
            Constraint::Length(5),
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
            format!("{} peers", self.view.peers.len())
        };
        let mut network = detail_line("network_id", self.view.overview.network_id.clone());
        if !self.can_revoke() {
            network.spans.push(Span::raw(" | read only"));
        }
        let mut host = detail_line("local_host", self.view.overview.local_name.clone());
        host.spans.push(Span::raw(" | "));
        host.spans.extend(
            detail_line(
                "transport",
                Span::styled(
                    if self.view.online {
                        "running"
                    } else {
                        "not_running"
                    },
                    Style::default()
                        .fg(if self.view.online {
                            Color::Green
                        } else {
                            Color::Red
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .spans,
        );
        host.spans.extend([
            Span::raw(" | "),
            Span::styled(counts, Style::default().fg(Color::LightBlue)),
        ]);
        if !self.view.online {
            host.spans.extend([
                Span::raw(" | "),
                Span::styled(
                    "connection_status:",
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::styled("unknown", Style::default().fg(Color::Gray)),
            ]);
        }
        frame.render_widget(
            Paragraph::new(vec![
                detail_line(
                    "network_label",
                    self.view
                        .overview
                        .network_label
                        .clone()
                        .unwrap_or_else(|| "not_recorded".into()),
                ),
                network,
                host,
            ])
            .block(Block::bordered().title(" esp admin ")),
            sections[0],
        );
        let columns = Layout::horizontal([
            Constraint::Percentage(22),
            Constraint::Percentage(30),
            Constraint::Percentage(48),
        ])
        .split(sections[1]);
        let panes = &columns[1..];
        let network_items: Vec<_> = self
            .networks
            .iter()
            .map(|n| {
                ListItem::new(vec![
                    Line::from(n.label.clone()),
                    Line::from(Span::styled(
                        n.role.clone(),
                        Style::default().fg(Color::Gray),
                    )),
                ])
            })
            .collect();
        frame.render_stateful_widget(
            List::new(network_items)
                .block(Block::bordered().title(if self.focus == 0 {
                    " Networks * "
                } else {
                    " Networks "
                }))
                .highlight_symbol("> ")
                .highlight_style(Style::default().bg(Color::DarkGray)),
            columns[0],
            &mut self.network_list,
        );
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
                Paragraph::new(format!(
                    "No joined peers.\n\nesp invite {:?} \"name\"",
                    self.view
                        .overview
                        .network_label
                        .as_deref()
                        .unwrap_or_default()
                ))
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(if self.focus == 1 {
                    " Peers * "
                } else {
                    " Peers "
                })),
                panes[0],
            );
        } else {
            frame.render_stateful_widget(
                List::new(items)
                    .block(Block::bordered().title(if self.focus == 1 {
                        " Peers * "
                    } else {
                        " Peers "
                    }))
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
                    "unknown"
                } else if peer.active_connections > 0 {
                    "connected"
                } else {
                    "disconnected"
                };
                let mut status_value = Span::styled(
                    status,
                    Style::default().fg(if self.view.online {
                        Color::LightBlue
                    } else {
                        Color::Gray
                    }),
                );
                if self.view.online && peer.active_connections > 0 {
                    status_value = status_value.style(
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    );
                }
                let mut text = vec![
                    detail_line("admin_label", peer.admin_label.clone()),
                    detail_line("hostname", peer.hostname.clone()),
                    detail_line("connection_id", peer.connection_id.clone()),
                    detail_line("node_id", peer.node_id.to_string()),
                    detail_line("status", status_value),
                ];
                if let Some(detail) = self
                    .detail
                    .as_ref()
                    .filter(|detail| detail.peer.node_id == peer.node_id)
                {
                    text.extend([
                        detail_line("role", detail.role.to_string()),
                        detail_line("allowed_ports", format_ports(&detail.allowed_ports)),
                        detail_line(
                            "invite_id",
                            detail.invite_id.clone().unwrap_or_else(|| {
                                if detail.inviter == peer.node_id {
                                    "None (network creator)".into()
                                } else {
                                    "Not recorded".into()
                                }
                            }),
                        ),
                        detail_line("inviter", detail.inviter.to_string()),
                        detail_line("joined", timestamp(Some(detail.joined_at))),
                        detail_line(
                            "active_connections",
                            if self.view.online {
                                peer.active_connections.to_string()
                            } else {
                                "Unknown".into()
                            },
                        ),
                        detail_line("last_connected", timestamp(detail.last_connected)),
                        Line::default(),
                        Line::from("Connection status and history are observed by this host."),
                    ]);
                } else {
                    text.extend([Line::default(), Line::from("Loading details...")]);
                }
                text
            }
        };
        let paragraph =
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(Block::bordered().title(if self.focus == 2 {
                    " Peer details * "
                } else {
                    " Peer details "
                }));
        self.scroll = self.scroll.min(
            paragraph
                .line_count(panes[1].width.saturating_sub(2))
                .saturating_sub(panes[1].height.saturating_sub(2) as usize)
                .min(u16::MAX as usize) as u16,
        );
        frame.render_widget(paragraph.scroll((self.scroll, 0)), panes[1]);
        frame.render_widget(
            Paragraph::new(format!(
                "Tab/Shift-Tab: focus | j/k: navigate | J/K: scroll details | r: revoke | q: quit\n{}",
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
                "  n     [ y ]"
            } else {
                "[ n ]     y"
            };
            frame.render_widget(Paragraph::new(format!("remove peer {} from network {:?}? y/n\nhost: {} ({})\nnode: {}\n\nActive connections will close. This peer must rejoin with a new invite.\n{}\ny: remove | n/Esc: cancel | Tab/arrows: choose | Enter: confirm", peer.admin_label, self.view.overview.network_label.as_deref().unwrap_or_default(), peer.hostname, peer.connection_id, peer.node_id, buttons))
                .wrap(Wrap { trim: false }).block(Block::bordered().title(" Confirm revocation ")), dialog);
        }
    }
}

fn detail_line(label: &str, value: impl Into<Span<'static>>) -> Line<'static> {
    let mut value = value.into();
    value.style = Style::default().fg(Color::LightBlue).patch(value.style);
    Line::from(vec![
        Span::styled(
            format!("{label}:"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        value,
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
    Networks(Result<Vec<NetworkRow>>),
    View(String, u64, Result<View>),
    Detail(String, u64, EndpointId, Result<PeerDetail>),
    Revoked(String, u64, Result<RevocationReport>),
}

pub(super) async fn run(preselect: Option<String>) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("esp admin requires an interactive terminal (use ssh -t for remote access)");
    }
    let networks = fetch_networks().await?;
    let initial = preselect
        .as_ref()
        .and_then(|label| networks.iter().find(|n| &n.label == label))
        .or_else(|| networks.first());
    if preselect.is_some()
        && !networks
            .iter()
            .any(|n| Some(&n.label) == preselect.as_ref())
    {
        bail!("requested network is not configured");
    }
    let mut app = App::new(empty_view(
        initial.map(|n| n.id.clone()).unwrap_or_default(),
        initial.map(|n| n.label.clone()).unwrap_or_default(),
    ));
    app.set_networks(networks);
    app.focus = 0;
    let mut terminal = ratatui::init();
    let _restore = RestoreTerminal;
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut jobs = tokio::task::JoinSet::new();
    let mut refreshing = false;
    let mut listing = false;
    let mut detail_job: Option<tokio::task::AbortHandle> = None;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        terminal.draw(|frame| app.render(frame))?;
        let mut refresh_detail = false;
        let mut refresh_view = false;
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tick.tick() => {
                if !listing { listing = true; jobs.spawn(async { Update::Networks(fetch_networks().await) }); }
                refresh_view = !refreshing && !app.revoking;
            }
            event = events.next() => {
                match event {
                    Some(Ok(Event::Key(key))) => match app.key(key) {
                        Action::Quit => break,
                        Action::Detail => refresh_detail = true,
                        Action::Network => { refresh_view = true; refreshing = false; },
                        Action::Revoke(node_id) => {
                            app.generation += 1;
                            let id = app.view.overview.network_id.clone(); let generation = app.generation;
                            jobs.spawn(async move { let result = async {
                                let response = networks::send(&networks::Request::Network { id: id.clone(), request: LocalControlRequest::Revoke { target: node_id.to_string() } }).await?.ok_or_else(|| anyhow!("local transport stopped; revocation was not applied"))?;
                                match response.network()? { LocalControlOk::Revoked { report } => Ok(report), _ => bail!("invalid revoke response") }
                            }.await; Update::Revoked(id, generation, result) });
                        }
                        Action::None => {},
                    },
                    Some(Ok(_)) => {}, Some(Err(e)) => return Err(e.into()), None => break,
                }
            }
            update = jobs.join_next(), if !jobs.is_empty() => {
                match update {
                    Some(Ok(Update::Networks(result))) => {
                        listing = false;
                        match result { Ok(networks) => { if app.set_networks(networks) { refreshing = false; refresh_view = true; } }, Err(e) => app.stale(format!("{e:#}")) }
                    }
                    Some(Ok(Update::View(id, generation, result))) => {
                        if id == app.view.overview.network_id && generation == app.generation {
                            refreshing = false;
                            match result { Ok(view) => { app.update(view); refresh_detail = true; }, Err(e) => app.stale(format!("{e:#}")) }
                        }
                    }
                    Some(Ok(Update::Detail(id, generation, node_id, result))) => {
                        if id == app.view.overview.network_id && generation == app.generation && app.selected().is_some_and(|p| p.node_id == node_id) {
                            match result { Ok(detail) => { app.accept_detail(&id, generation, detail); }, Err(e) => app.message = format!("{e:#}") }
                        }
                    }
                    Some(Ok(Update::Revoked(id, generation, result))) => {
                        if id == app.view.overview.network_id && generation == app.generation {
                            app.revoking = false; refreshing = false;
                            match result { Ok(report) => { let mut view = app.view.clone(); view.peers.retain(|p| p.node_id != report.node_id); app.update(view); app.message = format!("Revoked {}", report.display_name); }, Err(e) => app.stale(format!("Revocation failed: {e:#}")) }
                            refresh_view = true;
                        }
                    }
                    Some(Err(e)) if e.is_cancelled() => {}, Some(Err(e)) => return Err(e.into()), None => {},
                }
            }
        }
        if refresh_view && !app.view.overview.network_id.is_empty() {
            refreshing = true;
            let id = app.view.overview.network_id.clone();
            let generation = app.generation;
            jobs.spawn(async move {
                let result = fetch_view(&id).await;
                Update::View(id, generation, result)
            });
        }
        if refresh_detail {
            if let Some(job) = detail_job.take() {
                job.abort();
            }
            if let Some(peer) = app.selected() {
                let node_id = peer.node_id;
                let online = app.view.online;
                let id = app.view.overview.network_id.clone();
                let generation = app.generation;
                detail_job = Some(jobs.spawn(async move {
                    let result = fetch_detail(&id, node_id, online).await;
                    Update::Detail(id, generation, node_id, result)
                }));
            }
        }
    }
    jobs.abort_all();
    Ok(())
}
