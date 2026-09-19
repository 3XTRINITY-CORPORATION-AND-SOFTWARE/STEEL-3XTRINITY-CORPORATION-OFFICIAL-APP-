/**
 * STEEL art integration — drop into goliath-os / STEEL web remote.
 *
 * Behavior:
 *  1. On place change (os/web/host/aura/audit) → applySteelPhotoTheme(place)
 *     AND optionally applyAtlasCell(cellForPlace(place, index))
 *  2. Skin modes: photo | atlas | analog-neon
 *  3. No AudioWorklet changes.
 *
 * EN labels primary; ET optional via SKIN_LABELS / PLACE_LABELS.
 */

import {
  PHOTO_PLACE_MAP,
  normalizePlace,
  photoThemeForPlace,
  type SteelPlace,
  STEEL_PLACES,
  PLACE_LABELS,
} from "./placeMap";
import {
  STEEL_CSS_IMPORTS,
  STEEL_CSS_SIDE_EFFECTS,
  STEEL_SKINS,
  SKIN_LABELS,
  isSteelSkin,
  type SteelSkin,
} from "./skins";

export type { SteelPlace, SteelSkin };
export {
  PHOTO_PLACE_MAP,
  normalizePlace,
  photoThemeForPlace,
  STEEL_PLACES,
  PLACE_LABELS,
  STEEL_CSS_IMPORTS,
  STEEL_CSS_SIDE_EFFECTS,
  STEEL_SKINS,
  SKIN_LABELS,
  isSteelSkin,
};

const PHOTO_APPLY_URL = "/themes/steel-photo/apply-steel-photo-theme.js";
const ATLAS_APPLY_URL = "/atlas/steel-250/js/apply-atlas-cell.js";

export type ApplyPlaceArtOptions = {
  /** Atlas deck index within place-biased cells (default 0). */
  atlasIndex?: number;
  /** Force a skin for this call (else uses current skin). */
  skin?: SteelSkin;
  /** Also apply atlas cell when skin is photo (default true when skin=atlas only). */
  alsoAtlas?: boolean;
  root?: HTMLElement;
};

type AtlasApi = {
  loadAtlas: (url?: string) => Promise<unknown>;
  cellForPlace: (place: string, index?: number) => AtlasCell | null;
  applyAtlasCell: (
    id: string | AtlasCell,
    el?: HTMLElement,
    opts?: { thumbUrl?: string | false; dispatch?: boolean }
  ) => AtlasCell | null;
  getCell: (id: string) => AtlasCell | null;
  allCells: () => AtlasCell[];
};

type AtlasCell = {
  id: string;
  name?: string;
  family?: string;
  placeBias?: string;
  palette?: Record<string, string>;
  motion?: string;
  extraSlot?: number;
  bankOrPlugin?: string;
};

type PhotoApi = {
  applySteelPhotoTheme: (placeOrTheme: string) => unknown;
  STEEL_PHOTO_PLACE_MAP: Record<string, string>;
};

let _skin: SteelSkin = "photo";
let _place: SteelPlace = "os";
let _atlasIndex = 0;
let _atlasReady: Promise<AtlasApi> | null = null;
let _photoApi: PhotoApi | null = null;
let _atlasApi: AtlasApi | null = null;

async function loadPhotoApi(): Promise<PhotoApi> {
  if (_photoApi) return _photoApi;
  const mod = (await import(/* @vite-ignore */ PHOTO_APPLY_URL)) as PhotoApi;
  _photoApi = mod;
  return mod;
}

async function loadAtlasApi(): Promise<AtlasApi> {
  if (_atlasApi) return _atlasApi;
  if (!_atlasReady) {
    _atlasReady = (async () => {
      const mod = (await import(/* @vite-ignore */ ATLAS_APPLY_URL)) as AtlasApi;
      await mod.loadAtlas("/atlas/steel-250/atlas/atlas.json");
      _atlasApi = mod;
      return mod;
    })();
  }
  return _atlasReady;
}

function rootEl(el?: HTMLElement): HTMLElement {
  return el || (typeof document !== "undefined" ? document.documentElement : (null as unknown as HTMLElement));
}

function clearSkinAttrs(root: HTMLElement) {
  root.removeAttribute("data-steel-skin");
  // photo themes use data-theme; atlas uses data-atlas-cell — leave for active skin to set
}

/** Apply photo theme for a place (or explicit theme id). */
export async function applySteelPhotoTheme(placeOrTheme: string) {
  const api = await loadPhotoApi();
  return api.applySteelPhotoTheme(placeOrTheme);
}

/** Apply atlas cell by id or cell object. */
export async function applyAtlasCell(
  idOrCell: string | AtlasCell,
  el?: HTMLElement,
  opts?: { thumbUrl?: string | false; dispatch?: boolean }
) {
  const api = await loadAtlasApi();
  const cell =
    typeof idOrCell === "string" ? api.getCell(idOrCell) || idOrCell : idOrCell;
  return api.applyAtlasCell(cell as AtlasCell, rootEl(el), {
    thumbUrl:
      opts?.thumbUrl ??
      (typeof cell === "object" && cell && "id" in cell
        ? `/atlas/steel-250/assets/thumbs/${(cell as AtlasCell).id}.svg`
        : `/atlas/steel-250/assets/thumbs/${idOrCell}.svg`),
    dispatch: opts?.dispatch,
  });
}

export async function cellForPlace(place: string, index = 0) {
  const api = await loadAtlasApi();
  return api.cellForPlace(normalizePlace(place), index);
}

/** Apply analog-neon skin tokens + wash. */
export function applyAnalogNeon(el?: HTMLElement) {
  const root = rootEl(el);
  root.setAttribute("data-steel-skin", "analog-neon");
  root.style.setProperty(
    "--steel-wash-image",
    'url("/themes/steel-analog-neon/graded/analog-06-graded.jpg")'
  );
  // Map neon tokens onto STEEL chrome vars
  root.style.setProperty("--color-paper", "#050505");
  root.style.setProperty("--color-ink", "#f2f4ff");
  root.style.setProperty("--color-ember", "#ff2a4c");
  root.style.setProperty("--color-live", "#39ff88");
  root.style.setProperty("--color-steel", "#8a90a8");
  root.style.setProperty("--color-rule", "#1a1c24");
  return { skin: "analog-neon" as const };
}

/**
 * Primary hook: call on place / tab change.
 * - photo skin → applySteelPhotoTheme(place)
 * - atlas skin → applyAtlasCell(cellForPlace(place, index))
 * - analog-neon → applyAnalogNeon() (place-agnostic studio wash; still records place)
 */
export async function applyPlaceArt(
  place: string,
  opts: ApplyPlaceArtOptions = {}
) {
  const p = normalizePlace(place);
  _place = p;
  if (typeof opts.atlasIndex === "number") _atlasIndex = opts.atlasIndex;
  const skin = opts.skin ?? _skin;
  const root = rootEl(opts.root);

  root.setAttribute("data-steel-place", p);

  if (skin === "photo") {
    clearSkinAttrs(root);
    root.setAttribute("data-steel-skin", "photo");
    const meta = await applySteelPhotoTheme(p);
    if (opts.alsoAtlas) {
      const cell = await cellForPlace(p, _atlasIndex);
      if (cell) await applyAtlasCell(cell, root);
    }
    return { skin, place: p, photo: meta };
  }

  if (skin === "atlas") {
    clearSkinAttrs(root);
    root.setAttribute("data-steel-skin", "atlas");
    const cell = await cellForPlace(p, _atlasIndex);
    if (cell) await applyAtlasCell(cell, root);
    return { skin, place: p, cell };
  }

  // analog-neon
  applyAnalogNeon(root);
  root.setAttribute("data-steel-place", p);
  return { skin: "analog-neon" as const, place: p };
}

/** Switch global skin mode and re-apply for current place. */
export async function setSkin(skin: SteelSkin, opts?: ApplyPlaceArtOptions) {
  if (!isSteelSkin(skin)) throw new Error(`Unknown skin: ${skin}`);
  _skin = skin;
  if (typeof localStorage !== "undefined") {
    try {
      localStorage.setItem("steel-art-skin", skin);
    } catch {
      /* ignore */
    }
  }
  return applyPlaceArt(_place, { ...opts, skin });
}

export function getSkin(): SteelSkin {
  return _skin;
}

export function getPlace(): SteelPlace {
  return _place;
}

export function getAtlasIndex(): number {
  return _atlasIndex;
}

/** Cycle to next atlas cell within the current place deck. */
export async function cycleAtlas(delta = 1) {
  _atlasIndex = (_atlasIndex + delta) | 0;
  if (_skin !== "atlas") {
    _skin = "atlas";
  }
  return applyPlaceArt(_place, { skin: "atlas", atlasIndex: _atlasIndex });
}

/** Restore skin preference from localStorage (call once at boot). */
export function restoreSkinPreference(): SteelSkin {
  if (typeof localStorage === "undefined") return _skin;
  try {
    const v = localStorage.getItem("steel-art-skin");
    if (isSteelSkin(v)) _skin = v;
  } catch {
    /* ignore */
  }
  return _skin;
}

/**
 * Wire place getter — returns a sync function for shell place/tab listeners.
 * Example: const sync = await wireSteelArt(() => store.place);
 *          sync(); // on every place change
 */
export async function wireSteelArt(getPlace: () => string) {
  restoreSkinPreference();
  // Preload atlas when skin may need it
  if (_skin === "atlas") await loadAtlasApi();
  const sync = () => applyPlaceArt(getPlace());
  await sync();
  return sync;
}

/* -------------------------------------------------------------------------- */
/* Tiny React-ish Art menu snippet (copy into shell chrome)                   */
/* -------------------------------------------------------------------------- */

export const ART_MENU_SNIPPET = `
/* ArtMenu.tsx — drop into STEEL shell chrome (React-ish) */
import { useState, useEffect } from "react";
import {
  setSkin,
  getSkin,
  cycleAtlas,
  STEEL_SKINS,
  SKIN_LABELS,
  type SteelSkin,
} from "@/steel-art";

export function ArtMenu({ locale = "en" }: { locale?: "en" | "et" }) {
  const [skin, setLocal] = useState<SteelSkin>(getSkin());

  useEffect(() => {
    setLocal(getSkin());
  }, []);

  async function onPick(next: SteelSkin) {
    await setSkin(next);
    setLocal(next);
  }

  return (
    <div className="steel-art-menu" role="group" aria-label="Art">
      <span className="steel-art-menu__label">
        {locale === "et" ? "Kunst" : "Art"}
      </span>
      {STEEL_SKINS.map((id) => {
        const label =
          (locale === "et" && SKIN_LABELS[id].et) || SKIN_LABELS[id].en;
        return (
          <button
            key={id}
            type="button"
            className={skin === id ? "is-active" : undefined}
            aria-pressed={skin === id}
            title={SKIN_LABELS[id].description}
            onClick={() => onPick(id)}
          >
            {label}
          </button>
        );
      })}
      {skin === "atlas" && (
        <button type="button" onClick={() => cycleAtlas(1)} title="Next atlas cell">
          ⟳ Atlas
        </button>
      )}
    </div>
  );
}
`.trim();

export default {
  applyPlaceArt,
  setSkin,
  getSkin,
  getPlace,
  cycleAtlas,
  applySteelPhotoTheme,
  applyAtlasCell,
  cellForPlace,
  applyAnalogNeon,
  wireSteelArt,
  restoreSkinPreference,
  STEEL_CSS_IMPORTS,
  STEEL_CSS_SIDE_EFFECTS,
  ART_MENU_SNIPPET,
};
