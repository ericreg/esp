//! Read-only GNOME display discovery. This module never creates a monitor or
//! applies a layout; API availability alone does not prove mirror support.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, ensure};
use serde::Serialize;
use zbus::{Connection, Proxy, proxy::CacheProperties, zvariant::OwnedValue};

use super::display::{Display, Identity, Mode, Placement, Size};

const DESTINATION: &str = "org.gnome.Mutter.DisplayConfig";
const PATH: &str = "/org/gnome/Mutter/DisplayConfig";
const INTERFACE: &str = "org.gnome.Mutter.DisplayConfig";
const SCREENCAST_DESTINATION: &str = "org.gnome.Mutter.ScreenCast";

type Properties = HashMap<String, OwnedValue>;
type MonitorSpec = (String, String, String, String);
type RawMode = (String, i32, i32, f64, f64, Vec<f64>, Properties);
type RawMonitor = (MonitorSpec, Vec<RawMode>, Properties);
type RawLogicalMonitor = (i32, i32, f64, u32, bool, Vec<MonitorSpec>, Properties);
type CurrentState = (u32, Vec<RawMonitor>, Vec<RawLogicalMonitor>, Properties);

#[derive(Debug, Serialize)]
pub(super) struct Report {
    backend: &'static str,
    configuration_serial: u32,
    configuration_changes_allowed: Option<bool>,
    screencast_version: Option<i32>,
    mirror_support: &'static str,
    next_step: &'static str,
    displays: Vec<Display>,
}

impl Report {
    pub(super) fn print(&self, output: crate::output::Options) -> Result<()> {
        if output.format == crate::output::Format::Json {
            return output.print(&serde_json::to_value(self)?);
        }
        let mut sections = vec![output.render(&serde_json::json!({
            "backend": self.backend,
            "configuration_serial": self.configuration_serial,
            "configuration_changes_allowed": self.configuration_changes_allowed,
            "screencast_version": self.screencast_version,
            "mirror_support": self.mirror_support,
        }))?];
        for display in &self.displays {
            let size_text = |size: Size| format!("{}x{}", size.width, size.height);
            sections.push(output.render(&serde_json::json!({
                "display_id": display.id,
                "connector": display.identity.connector,
                "name": display.name,
                "active": display.active,
                "source_resolution": display.mode.as_ref().map(|mode| size_text(mode.pixels)),
                "scale": display.placement.as_ref().map(|placement| placement.scale),
                "transform": display.placement.as_ref().map(|placement| placement.transform),
                "mirrored_connectors": display.placement.as_ref().map(|placement| &placement.mirrored_connectors),
                "suggested_stream_resolution": display.suggested_stream_size.map(size_text),
                "source_unavailable_reason": display.source_unavailable_reason,
            }))?);
        }
        sections.push(self.next_step.to_owned());
        println!("{}", sections.join("\n\n"));
        Ok(())
    }
}

pub(super) async fn discover() -> Result<Report> {
    let connection = Connection::session().await.context(
        "cannot connect to the graphical session bus; run `esp video displays` in the GNOME graphical session",
    )?;
    discover_on(&connection).await
}

async fn owner(
    connection: &Connection,
    destination: &str,
) -> Result<Option<zbus::names::OwnedUniqueName>> {
    let bus = zbus::fdo::DBusProxy::new(connection).await?;
    match bus.get_name_owner(destination.try_into()?).await {
        Ok(owner) => Ok(Some(owner)),
        Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("cannot find session service {destination}"))
        }
    }
}

async fn discover_on(connection: &Connection) -> Result<Report> {
    // Address the current unique owner, so a compositor exit cannot trigger
    // D-Bus service activation or send a later call to a replacement process.
    let owner = owner(connection, DESTINATION).await?.context(
        "no running GNOME/Mutter display service on this session bus; run `esp video displays` from a GNOME graphical session"
    )?;
    let proxy = zbus::proxy::Builder::<Proxy>::new(connection)
        .destination(owner)?
        .path(PATH)?
        .interface(INTERFACE)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let state: CurrentState = proxy
        .call("GetCurrentState", &())
        .await
        .context("cannot read Mutter display state")?;
    let configuration_changes_allowed =
        optional_property::<bool>(&proxy, "ApplyMonitorsConfigAllowed").await?;
    let screencast_version =
        if let Some(owner) = self::owner(connection, SCREENCAST_DESTINATION).await? {
            let screencast = zbus::proxy::Builder::<Proxy>::new(connection)
                .destination(owner)?
                .path("/org/gnome/Mutter/ScreenCast")?
                .interface(SCREENCAST_DESTINATION)?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            optional_property::<i32>(&screencast, "Version").await?
        } else {
            None
        };
    let (serial, monitors, logical_monitors, _) = state;
    Ok(Report {
        backend: "gnome_mutter",
        configuration_serial: serial,
        configuration_changes_allowed,
        screencast_version,
        mirror_support: "not_yet_validated",
        next_step: "Display discovery is available. Virtual-mirror creation and video streaming are not implemented yet.",
        displays: parse_displays(monitors, logical_monitors)?,
    })
}

async fn optional_property<T>(proxy: &Proxy<'_>, name: &str) -> Result<Option<T>>
where
    T: TryFrom<OwnedValue>,
    T::Error: Into<zbus::Error>,
{
    match proxy.get_property(name).await {
        Ok(value) => Ok(Some(value)),
        Err(zbus::Error::FDO(error)) if matches!(*error, zbus::fdo::Error::UnknownProperty(_)) => {
            Ok(None)
        }
        Err(zbus::Error::MethodError(error, _, _))
            if error.as_str() == "org.freedesktop.DBus.Error.UnknownProperty" =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| format!("cannot read Mutter property {name}")),
    }
}

fn property<T>(properties: &Properties, key: &str) -> Result<Option<T>>
where
    for<'a> T: TryFrom<&'a OwnedValue>,
    for<'a> <T as TryFrom<&'a OwnedValue>>::Error: std::error::Error + Send + Sync + 'static,
{
    properties
        .get(key)
        .map(|value| T::try_from(value).with_context(|| format!("invalid Mutter property {key}")))
        .transpose()
}

fn parse_displays(
    monitors: Vec<RawMonitor>,
    logical: Vec<RawLogicalMonitor>,
) -> Result<Vec<Display>> {
    let mut specs = HashSet::new();
    let mut connectors = HashSet::new();
    for (spec, _, _) in &monitors {
        ensure!(!spec.0.is_empty(), "empty Mutter monitor connector");
        ensure!(
            specs.insert(spec.clone()) && connectors.insert(spec.0.clone()),
            "duplicate Mutter monitor connector"
        );
    }

    let mut placements = HashMap::new();
    for (x, y, scale, transform, primary, members, _) in logical {
        ensure!(
            scale.is_finite() && scale > 0.0,
            "invalid Mutter monitor scale"
        );
        ensure!(
            transform <= 7,
            "unknown Mutter monitor transform {transform}"
        );
        ensure!(!members.is_empty(), "empty Mutter logical monitor");
        let mirrored_connectors = members
            .iter()
            .map(|spec| spec.0.clone())
            .collect::<Vec<_>>();
        for spec in members {
            ensure!(
                specs.contains(&spec),
                "logical monitor references a missing or replaced physical display"
            );
            let placement = Placement {
                x,
                y,
                scale,
                transform,
                primary,
                mirrored_connectors: mirrored_connectors.clone(),
            };
            ensure!(
                placements.insert(spec, placement).is_none(),
                "display appears in multiple logical monitors"
            );
        }
    }

    let mut displays = Vec::with_capacity(monitors.len());
    for ((connector, vendor, product, serial), modes, properties) in monitors {
        let identity = Identity {
            connector,
            vendor,
            product,
            serial,
        };
        let placement = placements.remove(&(
            identity.connector.clone(),
            identity.vendor.clone(),
            identity.product.clone(),
            identity.serial.clone(),
        ));
        let mut current = None;
        for (id, width, height, refresh_hz, _, _, mode_properties) in modes {
            if !property::<bool>(&mode_properties, "is-current")?.unwrap_or(false) {
                continue;
            }
            ensure!(current.is_none(), "display has multiple current modes");
            ensure!(
                !id.is_empty()
                    && width >= 2
                    && height >= 2
                    && refresh_hz.is_finite()
                    && refresh_hz > 0.0,
                "invalid current display mode"
            );
            current = Some(Mode {
                id,
                pixels: Size {
                    width: width as u32,
                    height: height as u32,
                },
                refresh_hz,
            });
        }
        ensure!(
            placement.is_some() == current.is_some(),
            "active display layout and current mode disagree"
        );
        let name = properties
            .get("display-name")
            .map(|value| <&str>::try_from(value).map(str::to_owned))
            .transpose()
            .context("invalid Mutter property display-name")?
            .unwrap_or_else(|| identity.connector.clone());
        let color_mode = property::<u32>(&properties, "color-mode")?.unwrap_or(0);
        let candidate_size = match (&current, &placement) {
            (Some(mode), Some(placement)) => {
                if !matches!(color_mode, 0 | 2) {
                    Err(anyhow!(
                        "HDR or unknown color mode is not supported in the initial video mode"
                    ))
                } else {
                    mode.pixels
                        .validate_source()
                        .and_then(|size| size.transformed(placement.transform))
                        .and_then(|size| {
                            size.fit(Size {
                                width: 1920,
                                height: 1080,
                            })
                        })
                }
            }
            _ => Err(anyhow!("display is inactive")),
        };
        let (suggested_stream_size, source_unavailable_reason) = match candidate_size {
            Ok(size) => (Some(size), None),
            Err(error) => (None, Some(error.to_string())),
        };
        displays.push(Display {
            id: identity.id(),
            identity,
            name,
            active: placement.is_some(),
            mode: current,
            placement,
            suggested_stream_size,
            source_unavailable_reason,
        });
    }
    displays.sort_by(|a, b| a.identity.connector.cmp(&b.identity.connector));
    Ok(displays)
}

#[cfg(test)]
#[path = "mutter_tests.rs"]
mod tests;
