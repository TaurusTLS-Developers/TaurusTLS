unit TaurusTLSLoader.TestHooks;

{ Optional loader diagnostics for UNITTEST builds.
  Register callbacks before any loader access, while initialization is still
  single-threaded. Leave them assigned until all loader users have stopped.
  This unit has no dependency on the loader or on any particular test project. }

interface

{$IFDEF UNITTEST}
type
  TLoaderTestFactory = function: IInterface;
  TLoaderAccessTestHook = procedure(AFactory: TLoaderTestFactory);
  TLoaderCandidateTestHook = procedure;

var
  // Receives a factory for the real loader path; must guard recursive entry.
  OnLoaderAccess: TLoaderAccessTestHook;
  // Runs after construction and acquisition of ownership, before publication.
  OnLoaderCandidateReady: TLoaderCandidateTestHook;
  // Runs after the base loader's locks have been released during destruction.
  OnLoaderCandidateDestroyed: TLoaderCandidateTestHook;
{$ENDIF}

implementation

end.

