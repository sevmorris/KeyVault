import Foundation

/// What the sidebar has selected.
///
/// A type of its own rather than a plain `KeyType?`, because a `List` whose
/// selection binding is optional cannot select a row tagged `nil`: `nil` is
/// how that binding spells "nothing is selected", so clicking the row meaning
/// "everything" cleared the selection instead of setting it, and the row could
/// never appear selected. The original "All Keys" row had the same defect and
/// only looked correct because the app happened to launch with nothing
/// selected, which made it look picked without ever having been picked.
enum SidebarSelection: Hashable {
    case everything
    case type(KeyType)
}
