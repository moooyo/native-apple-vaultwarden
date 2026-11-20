enum VaultSurfaceRole {
    case content
    case floatingAccessory

    func material(reduceTransparency: Bool, increaseContrast: Bool) -> VaultSurfaceMaterial {
        switch self {
        case .content:
            return .opaque
        case .floatingAccessory:
            return reduceTransparency || increaseContrast ? .opaque : .regularGlass
        }
    }
}

enum VaultSurfaceMaterial: Equatable {
    case opaque
    case regularGlass
}
